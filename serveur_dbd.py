#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Serveur du jeu DBD Killer (TurboWarp).

Il fait trois choses :
  1. il relaie les variables cloud entre les joueurs, avec le même protocole que le serveur cloud de TurboWarp
     (le jeu s'y connecte donc comme à n'importe quel serveur cloud) ;
  2. il tient les comptes : pseudo + mot de passe, supprimés après 3 jours sans connexion ;
  3. il tient plusieurs « serveurs » de jeu (20 par défaut, 5 joueurs chacun) et deux files d'attente, une pour les tueurs et une pour
     les survivants. Chaque joueur ne reçoit que les paquets de son propre serveur : 20 parties en même temps ne pèsent pas plus
     qu'une seule sur l'ordinateur d'un joueur. Quand tous les serveurs sont pris, le joueur attend dans la file et voit sa position
     et le temps d'attente estimé. À la fin d'une partie, s'il y a du monde dans la file, les joueurs de cette partie repassent
     derrière ceux qui attendaient.

Lancement :   pip install websockets
              python3 serveur_dbd.py                 (port 9080, comptes dans comptes.json)
              python3 serveur_dbd.py --port 8000 --comptes /chemin/comptes.json
              python3 serveur_dbd.py --sans-comptes  (pas de comptes : un pseudo suffit)
              python3 serveur_dbd.py --serveurs 12   (nombre de parties en même temps : 20 par défaut, soit 100 joueurs)
              python3 serveur_dbd.py --sans-files    (un seul salon pour tout le monde, comme avant)

Sur internet, il doit être servi en wss:// (derrière un hébergeur ou un proxy qui fait le TLS).
Les mots de passe ne sont jamais écrits tels quels : seul un hachage salé (PBKDF2) est enregistré.
"""
import argparse, asyncio, hashlib, hmac, json, os, re, secrets, sys, time

try:
    import websockets
except ImportError:
    sys.exit("Il manque le module 'websockets' :  pip install websockets")

# ---------------------------------------------------------------- réglages
JOURS_AVANT_SUPPRESSION = 3
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789_-.!?@#$%&*+="   # 2 chiffres par caractère : 01, 02, ...
PSEUDO_OK = re.compile(r"^[a-z0-9_-]{3,10}$")
MDP_MIN, MDP_MAX = 4, 16
VAR_DEMANDE = "☁ rq"      # le jeu y écrit ses demandes (créer un compte, se connecter) : jamais relayé aux autres
VAR_REPONSE = "☁ rp"      # le serveur y répond, seulement au joueur concerné
# ce que le serveur met dans la variable de réponse à l'arrivée : 7301 « ici il y a des comptes », 7302 « des files d'attente », 7303 « les deux »
BONJOUR_COMPTES, BONJOUR_FILES, BONJOUR_TOUT = "7301", "7302", "7303"
VARS_PLACES = {"☁ k%d" % i for i in range(5)}     # une variable par place du salon (0 = tueur, 1 à 4 = survivants)
VARS_JEU = VARS_PLACES | {"☁ etat", "☁ init"}     # tout ce qui appartient à un serveur de jeu
SERVEURS = 20                  # parties en même temps (5 joueurs chacune)
PLACES = (1, 4)                # par serveur : 1 tueur, 4 survivants
DUREE_DEFAUT = 480             # durée d'une partie tant qu'aucune n'a été mesurée (secondes)
FIN_PARTIE = 20                # entre la fin d'une partie et le retour au salon (écran de fin)
VALEUR_OK = re.compile(r"^-?\d+(\.\d+)?$")
LONGUEUR_MAX = 100000
MAX_VARS = 32
MAX_JOUEURS_PAR_SALLE = 400
ESSAIS_MAX = 6                 # mots de passe faux tolérés par connexion et par minute
ITER = 120000

# codes de réponse (dernier chiffre de la réponse)
OK_CREE, OK_CONNECTE, PSEUDO_PRIS, MAUVAIS_MDP, INCONNU, INVALIDE, TROP_ESSAIS, DEJA_LA = 1, 2, 3, 4, 5, 6, 7, 8


def log(*a):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *a, flush=True)


def decode_texte(chiffres):
    """'010203' -> 'abc' (None si un code ne correspond à rien)"""
    if len(chiffres) % 2: return None
    out = []
    for i in range(0, len(chiffres), 2):
        k = int(chiffres[i:i + 2])
        if not 1 <= k <= len(ALPHABET): return None
        out.append(ALPHABET[k - 1])
    return "".join(out)


class Comptes:
    def __init__(self, chemin):
        self.chemin = chemin; self.data = {}
        if chemin and os.path.exists(chemin):
            try: self.data = json.load(open(chemin, encoding="utf-8"))
            except Exception as e: log("comptes illisibles, on repart de zéro :", e)
        self.purger()

    def sauver(self):
        if not self.chemin: return
        tmp = self.chemin + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f: json.dump(self.data, f)
        os.replace(tmp, self.chemin)

    def purger(self):
        limite = time.time() - JOURS_AVANT_SUPPRESSION * 86400
        vieux = [p for p, c in self.data.items() if c.get("vu", 0) < limite]
        for p in vieux: del self.data[p]
        if vieux:
            log("comptes supprimés (plus de %d jours sans connexion) :" % JOURS_AVANT_SUPPRESSION, ", ".join(vieux)); self.sauver()
        return vieux

    @staticmethod
    def _hash(mdp, sel):
        return hashlib.pbkdf2_hmac("sha256", mdp.encode(), bytes.fromhex(sel), ITER).hex()

    def creer(self, pseudo, mdp):
        self.purger()
        if pseudo in self.data: return PSEUDO_PRIS
        sel = secrets.token_hex(16)
        self.data[pseudo] = {"sel": sel, "hash": self._hash(mdp, sel), "cree": time.time(), "vu": time.time()}
        self.sauver(); return OK_CREE

    def connecter(self, pseudo, mdp):
        self.purger()
        c = self.data.get(pseudo)
        if not c: return INCONNU
        if not hmac.compare_digest(self._hash(mdp, c["sel"]), c["hash"]): return MAUVAIS_MDP
        c["vu"] = time.time(); self.sauver(); return OK_CONNECTE


class Joueur:
    def __init__(self, ws):
        self.ws = ws; self.salle = None; self.nom = ""; self.pseudo = None; self.rates = []
        self.partie = None; self.role = None; self.var_place = None; self.dernier = ""; self.n = 0


class Partie:
    """un serveur de jeu : ses variables, ses joueurs (1 tueur et 4 survivants au plus)"""
    def __init__(self, numero):
        self.numero = numero; self.vars = {}; self.membres = []; self.en_jeu = False; self.debut = 0.0

    def libres(self, role):
        return PLACES[role] - sum(1 for m in self.membres if m.role == role)


class Serveur:
    def __init__(self, comptes, serveurs=SERVEURS):
        self.comptes = comptes          # None : simple relais, sans comptes
        self.serveurs = serveurs        # 0 : pas de files d'attente, un seul salon pour tout le monde
        self.salles = {}                # identifiant du projet -> {'vars': {...}, 'joueurs': set(), 'parties': [...], 'files': [[], []], 'durees': [...]}
        self.latence = 0; self.attente = {}

    # ------------------------------------------------------------ serveurs de jeu et files d'attente
    def diffuser(self, joueurs, nom, valeur):
        """la même valeur à plusieurs joueurs : écrite une seule fois, envoyée sans attendre"""
        if not joueurs: return
        if self.latence > 0 or not hasattr(websockets, "broadcast"):
            for o in joueurs: asyncio.ensure_future(self.envoyer(o, nom, valeur))
        else:
            websockets.broadcast([o.ws for o in joueurs], json.dumps({"method": "set", "name": nom, "value": valeur}))

    def dire(self, j, texte):
        """un message du serveur à un seul joueur, dans la variable de réponse (un compteur à la fin : deux messages de suite ne sont jamais égaux)"""
        j.n = (j.n + 1) % 10
        asyncio.ensure_future(self.envoyer(j, VAR_REPONSE, texte + str(j.n)))

    def duree(self, salle):
        d = salle["durees"]; return min(1200, max(120, sum(d) / len(d))) if d else DUREE_DEFAUT

    def attente_estimee(self, salle, role, position):
        """secondes avant qu'une place se libère pour le joueur numéro `position` de la file"""
        maintenant = time.time(); D = self.duree(salle)
        fins = sorted((max(10, D - (maintenant - p.debut)) + FIN_PARTIE) if p.en_jeu else (D + FIN_PARTIE) for p in salle["parties"] if p.membres)
        if not fins: return 0
        k = (position - 1) // PLACES[role]            # combien de parties doivent finir avant la sienne
        return int(fins[k % len(fins)] + (k // len(fins)) * (D + FIN_PARTIE))

    def etat_file(self, salle, j):
        f = salle["files"][j.role]; pos = f.index(j) + 1
        en_jeu = sum(1 for p in salle["parties"] if p.en_jeu)
        return "6%d%03d%04d%03d%02d%02d" % (j.role, min(pos, 999), min(self.attente_estimee(salle, j.role, pos), 9999), min(len(salle["joueurs"]), 999), en_jeu, len(salle["parties"]))

    def annoncer_files(self, salle):
        for f in salle["files"]:
            for j in f:
                t = self.etat_file(salle, j)
                if t != j.dernier: j.dernier = t; self.dire(j, t)

    def entrer(self, salle, j, p):
        j.partie = p; p.membres.append(j); j.var_place = None; j.dernier = ""
        lignes = [json.dumps({"method": "set", "name": n, "value": p.vars.get(n, "0")}) for n in sorted(VARS_JEU)]
        asyncio.ensure_future(self.brut(j, "\n".join(lignes)))
        self.dire(j, "5%02d%d" % (p.numero, j.role))
        log("serveur %d : + %s (%s), %d joueur(s)" % (p.numero, j.pseudo or j.nom or "?", "tueur" if j.role == 0 else "survivant", len(p.membres)))

    def sortir(self, salle, j, prevenir=True):
        """le joueur quitte son serveur de jeu : sa place est libérée chez les autres, et il ne voit plus rien de ce serveur"""
        p = j.partie
        if p is None: return
        p.membres.remove(j); j.partie = None
        if j.var_place:
            p.vars[j.var_place] = "0"; self.diffuser(p.membres, j.var_place, "0")
            if j.var_place == "☁ k0" and p.en_jeu: self.fin_partie(salle, p, tourner=False)
        j.var_place = None
        if not p.membres: p.vars.clear(); p.en_jeu = False
        if prevenir:
            asyncio.ensure_future(self.brut(j, "\n".join(json.dumps({"method": "set", "name": n, "value": "0"}) for n in sorted(VARS_JEU))))

    def placer(self, salle):
        """tant qu'un joueur en file peut entrer quelque part, il entre : d'abord dans le serveur le plus rempli (celui qui a déjà son tueur, pour un survivant)"""
        for role in (0, 1):
            f = salle["files"][role]
            while f:
                ouverts = [p for p in salle["parties"] if not p.en_jeu and p.libres(role) > 0]
                if not ouverts: break
                p = max(ouverts, key=lambda p: (len(p.membres), PLACES[0] - p.libres(0), -p.numero))
                self.entrer(salle, f.pop(0), p)
        self.annoncer_files(salle)

    def fin_partie(self, salle, p, tourner=True):
        if p.en_jeu and time.time() - p.debut > 60:
            salle["durees"].append(time.time() - p.debut); del salle["durees"][:-20]
        p.en_jeu = False
        if not tourner: return
        # du monde attend ce rôle : ceux qui viennent de jouer repassent derrière eux
        for role in (0, 1):
            if salle["files"][role]:
                for m in [m for m in p.membres if m.role == role]:
                    self.sortir(salle, m); salle["files"][role].append(m)
        self.placer(salle)

    async def file(self, j, valeur):
        """'3' + numéro(4) + rôle(1) : entrer dans la file des tueurs (0) ou des survivants (1) ; '4' + numéro(4) : quitter la file ou son serveur"""
        salle = j.salle
        if j.role is not None:
            if j in salle["files"][j.role]: salle["files"][j.role].remove(j)
            self.sortir(salle, j); j.role = None
        if valeur[0] == "3" and len(valeur) >= 6 and valeur[5] in "01" and (self.comptes is None or j.pseudo is not None):
            j.role = int(valeur[5]); j.dernier = ""; salle["files"][j.role].append(j)
        else:
            self.dire(j, "4")
        self.placer(salle)

    async def brut(self, j, texte):
        if self.latence > 0: await asyncio.sleep(self.latence)
        try: await j.ws.send(texte)
        except Exception: pass

    async def envoyer(self, j, nom, valeur):
        if self.latence > 0:
            # (pour les tests : imite un serveur lointain -- chaque envoi part avec du retard, et seule la dernière valeur d'une variable est gardée)
            cle = (id(j), nom)
            if cle in self.attente: self.attente[cle] = valeur; return
            self.attente[cle] = valeur; await asyncio.sleep(self.latence); valeur = self.attente.pop(cle, valeur)
        try: await j.ws.send(json.dumps({"method": "set", "name": nom, "value": valeur}))
        except Exception: pass

    def connectes(self, salle):
        return {j.pseudo for j in salle["joueurs"] if j.pseudo}

    async def demande(self, j, valeur):
        """une demande de compte : '1' + numéro(4) + opération(1) + longueur(2) + pseudo + longueur(2) + mot de passe"""
        v = str(valeur)
        if len(v) < 10 or v[0] != "1": return
        rid, op = v[1:5], v[5]
        async def rep(code): await self.envoyer(j, VAR_REPONSE, "2" + rid + str(code))
        try:
            n = int(v[6:8]); pseudo = decode_texte(v[8:8 + 2 * n]); p = 8 + 2 * n
            m = int(v[p:p + 2]); mdp = decode_texte(v[p + 2:p + 2 + 2 * m])
        except Exception:
            return await rep(INVALIDE)
        if not pseudo or mdp is None or not PSEUDO_OK.match(pseudo) or not MDP_MIN <= len(mdp) <= MDP_MAX or op not in "12":
            return await rep(INVALIDE)
        maintenant = time.time(); j.rates = [t for t in j.rates if maintenant - t < 60]
        if len(j.rates) >= ESSAIS_MAX: return await rep(TROP_ESSAIS)
        code = self.comptes.creer(pseudo, mdp) if op == "1" else self.comptes.connecter(pseudo, mdp)
        # le bon mot de passe, mais ce compte joue déjà depuis une autre fenêtre
        if code == OK_CONNECTE and j.pseudo != pseudo and pseudo in self.connectes(j.salle): code = DEJA_LA
        if code in (OK_CREE, OK_CONNECTE):
            j.pseudo = pseudo; log("compte", "créé :" if code == OK_CREE else "connecté :", pseudo)
        else:
            j.rates.append(maintenant)
        await rep(code)

    def place_valide(self, j, valeur):
        """une présence au salon ('1' + identifiant(5) + battement(2) + prêt(1) + longueur(2) + pseudo) doit porter le pseudo du compte connecté"""
        v = str(valeur)
        if not v or v[0] != "1": return True            # paquets de partie, ou place libérée
        if j.pseudo is None: return False               # pas connecté à un compte : pas de place au salon
        # (le pseudo est à la fin du paquet, après un en-tête qui a grandi avec les versions du jeu : personnage, objet, compétences)
        for entete in (9, 12, 14):
            try:
                n = int(v[entete:entete + 2])
                if len(v) == entete + 2 + 2 * n: return decode_texte(v[entete + 2:]) == j.pseudo
            except Exception:
                pass
        return False

    async def recevoir(self, j, msg):
        m = msg.get("method")
        if m == "handshake":
            pid = str(msg.get("project_id", ""))[:100]
            salle = self.salles.setdefault(pid, {"vars": {}, "joueurs": set(), "parties": [Partie(i + 1) for i in range(self.serveurs)], "files": [[], []], "durees": []})
            if len(salle["joueurs"]) >= MAX_JOUEURS_PAR_SALLE:
                await j.ws.close(4003, "salle pleine"); return
            j.salle = salle; j.nom = str(msg.get("user", ""))[:40]; salle["joueurs"].add(j)
            lignes = [json.dumps({"method": "set", "name": n, "value": v}) for n, v in salle["vars"].items()]
            bonjour = (BONJOUR_TOUT if self.serveurs else BONJOUR_COMPTES) if self.comptes is not None else (BONJOUR_FILES if self.serveurs else None)
            if bonjour: lignes.append(json.dumps({"method": "set", "name": VAR_REPONSE, "value": bonjour}))
            if lignes: await j.ws.send("\n".join(lignes))
            return
        if j.salle is None: return
        if m in ("set", "create"):
            nom, valeur = msg.get("name"), msg.get("value")
            if not isinstance(nom, str) or not nom.startswith("☁ ") or len(nom) > 100: return
            valeur = str(valeur)
            if len(valeur) > LONGUEUR_MAX or not VALEUR_OK.match(valeur): return
            if nom == VAR_DEMANDE:
                if self.serveurs and valeur[0] in "34": return await self.file(j, valeur)
                if self.comptes is not None: return await self.demande(j, valeur)
                return
            if nom == VAR_REPONSE and (self.comptes is not None or self.serveurs): return      # seul le serveur écrit ici
            if self.comptes is not None and nom in VARS_PLACES and not self.place_valide(j, valeur): return
            if self.serveurs and nom in VARS_JEU:
                # un paquet de jeu : il ne sort pas du serveur de jeu du joueur
                p = j.partie
                if p is None: return
                if nom in VARS_PLACES:
                    # (un tueur n'écrit que sur la place du tueur, un survivant sur une place de survivant)
                    if (nom == "☁ k0") != (j.role == 0): return
                    if valeur != "0": j.var_place = nom
                    elif j.var_place == nom: j.var_place = None
                p.vars[nom] = valeur
                self.diffuser([o for o in p.membres if o is not j], nom, valeur)
                if nom == "☁ k0":
                    if valeur[0] == "3" and not p.en_jeu:
                        p.en_jeu = True; p.debut = time.time(); log("serveur %d : la partie commence (%d joueurs)" % (p.numero, len(p.membres))); self.annoncer_files(j.salle)
                    elif valeur[0] != "3" and p.en_jeu:
                        log("serveur %d : partie finie après %d s" % (p.numero, time.time() - p.debut)); self.fin_partie(j.salle, p)
                return
            if nom not in j.salle["vars"] and len(j.salle["vars"]) >= MAX_VARS: return
            j.salle["vars"][nom] = valeur
            self.diffuser([o for o in j.salle["joueurs"] if o is not j], nom, valeur)
        # (rename / delete : le jeu ne s'en sert pas)

    async def connexion(self, ws, *_):
        j = Joueur(ws)
        try:
            async for brut in ws:
                if isinstance(brut, bytes): continue
                for ligne in brut.split("\n"):
                    if not ligne.strip(): continue
                    try: msg = json.loads(ligne)
                    except Exception: continue
                    if isinstance(msg, dict): await self.recevoir(j, msg)
        except Exception:
            pass
        finally:
            if j.salle is not None:
                j.salle["joueurs"].discard(j)
                if j.role is not None:
                    if j in j.salle["files"][j.role]: j.salle["files"][j.role].remove(j)
                    self.sortir(j.salle, j, prevenir=False); j.role = None; self.placer(j.salle)
                if not j.salle["joueurs"]: j.salle["vars"].clear()      # salle vide : on oublie tout, comme le serveur public

    async def menage(self):
        while True:
            await asyncio.sleep(3600)
            if self.comptes is not None: self.comptes.purger()

    async def horloge(self):
        """toutes les 2 secondes : la position et l'attente de ceux qui sont dans une file"""
        while True:
            await asyncio.sleep(2)
            for salle in self.salles.values():
                if salle["files"][0] or salle["files"][1]: self.annoncer_files(salle)


async def main():
    ap = argparse.ArgumentParser(description="Serveur DBD Killer : variables cloud + comptes")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", 9080)))
    ap.add_argument("--hote", default="0.0.0.0")
    ap.add_argument("--comptes", default="comptes.json", help="fichier où les comptes sont enregistrés")
    ap.add_argument("--sans-comptes", action="store_true", help="pas de comptes : un pseudo suffit")
    ap.add_argument("--serveurs", type=int, default=int(os.environ.get("SERVEURS", SERVEURS)), help="parties en même temps (5 joueurs chacune)")
    ap.add_argument("--sans-files", action="store_true", help="un seul salon pour tout le monde, sans files d'attente")
    ap.add_argument("--latence", type=float, default=0, help="(tests) retard ajouté à chaque envoi, en secondes")
    a = ap.parse_args()
    srv = Serveur(None if a.sans_comptes else Comptes(a.comptes), 0 if a.sans_files else max(1, min(99, a.serveurs))); srv.latence = a.latence
    asyncio.get_running_loop().create_task(srv.menage()); asyncio.get_running_loop().create_task(srv.horloge())
    log("serveur prêt sur le port", a.port, "(sans comptes)" if a.sans_comptes else "(comptes : %s, %d enregistrés)" % (a.comptes, len(srv.comptes.data)),
        "- %d serveurs de jeu, %d joueurs en même temps" % (srv.serveurs, 5 * srv.serveurs) if srv.serveurs else "- un seul salon")
    # une simple visite de l'adresse dans un navigateur (ou le contrôle de l'hébergeur) reçoit « en marche » au lieu d'une erreur
    def visite(connexion, requete):
        try:
            if requete.headers.get("Upgrade", "").lower() != "websocket":
                return connexion.respond(200, "Serveur Dead by Nightlight en marche\n")
        except Exception:
            return None
    try:
        service = websockets.serve(srv.connexion, a.hote, a.port, max_size=2 ** 20, ping_interval=20, ping_timeout=20, process_request=visite)
    except TypeError:
        service = websockets.serve(srv.connexion, a.hote, a.port, max_size=2 ** 20, ping_interval=20, ping_timeout=20)
    async with service:
        await asyncio.Future()

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: pass
