# NetMap

Cartographie des appareils connectés au réseau local, affichée sur une page web.

- **Découverte** : scan ARP actif (Scapy) ; repli automatique en *ping sweep + table ARP* si le process n'a pas les droits réseau bruts.
- **Enrichissement** : nom d'hôte (DNS inverse), fabricant (OUI de la MAC), ports courants ouverts (ssh, http, smb, rdp, imprimante, Home Assistant, Proxmox, Plex…), type d'appareil deviné.
- **Historique** : SQLite — première/dernière apparition, statut en ligne, nom personnalisé.
- **Interface** : graphe en étoile autour de la box (vis-network), tableau filtrable, détail par appareil avec liens vers ses interfaces web. Les appareils apparus depuis moins de 24 h sont surlignés en orange.

## Lancer avec Docker (recommandé, Linux)

```bash
docker compose up -d --build
```

Puis ouvrir http://localhost:8000 (ou `http://<ip-de-la-machine>:8000` depuis un autre poste).

> `network_mode: host` ne fonctionne vraiment que sous Linux. Sous Docker Desktop (Windows/macOS) le conteneur ne voit pas le LAN : lance plutôt l'appli directement.

## Lancer sans Docker

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
sudo .venv/bin/uvicorn app:app --host 0.0.0.0 --port 8000
```

Sans `sudo`, ça marche quand même en mode dégradé (ping + table ARP, un peu plus lent et moins exhaustif). Pour éviter de lancer en root :

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f .venv/bin/python)"
```

Tester le scanner seul : `sudo .venv/bin/python scanner.py`

## Configuration (variables d'environnement)

| Variable | Défaut | Rôle |
|---|---|---|
| `SCAN_INTERVAL` | `300` | Secondes entre deux scans automatiques |
| `PORT_SCAN` | `1` | `0` pour ne pas tester les ports |
| `NETWORK_CIDR` | auto | Force le réseau à scanner, ex. `192.168.1.0/24` |
| `DB_PATH` | `data/netmap.db` | Emplacement de la base SQLite |

## API

| Méthode | Route | Description |
|---|---|---|
| GET | `/api/devices` | Tous les appareils connus |
| GET | `/api/status` | Réseau, passerelle, état du scan, dernière erreur |
| POST | `/api/scan` | Lance un scan immédiat |
| PATCH | `/api/devices/{mac}` | `{"label": "NAS salon"}` — renomme |
| DELETE | `/api/devices/{mac}` | Oublie un appareil |

## Limites connues

- Les téléphones récents utilisent des **MAC aléatoires** par réseau : le fabricant est alors inconnu (affiché « MAC privée »), et un même téléphone peut réapparaître comme nouvel appareil s'il change d'adresse.
- Le scan ARP ne traverse pas les routeurs : seul le sous-réseau de la machine qui héberge NetMap est vu (pas les VLAN séparés).
- Certains appareils ne répondent pas au DNS inverse : renseigne un nom personnalisé dans l'interface.
- À n'utiliser que sur un réseau qui t'appartient ou que tu administres.
