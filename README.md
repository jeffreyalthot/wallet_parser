# wallet_parser

Parser maison de `wallet.dat` **sans** `bsddb3`, **sans** `pywallet`, **sans** Bitcoin Core / RPC / bitcoin-lib.

## Fonctionnalités
- Lecture bas niveau des pages Berkeley DB (heuristique) pour extraire les blobs clé/valeur.
- Décodage des enregistrements usuels (`mkey`, `ckey`, `key`, `name`, `purpose`, ...).
- Support de `walletpassphrase` (argument `--walletpassphrase` ou saisie interactive).
- Option `--out` pour enregistrer le JSON généré.
- Déchiffrement des `ckey` via `openssl` (AES-256-CBC), sans dépendance Python crypto externe.
- Pour chaque `ckey` déchiffrée valide, calcul de l'adresse `p2pkh`, de la clé privée hex et du WIF.

## Usage
```bash
python3 wallet_parser.py /chemin/wallet.dat --walletpassphrase "ma phrase" --out resultat.json
```

Ou sans fournir la passphrase en ligne de commande (prompt sécurisé):
```bash
python3 wallet_parser.py /chemin/wallet.dat --out resultat.json
```

## Format de sortie
Le JSON inclut:
- `records`: enregistrements détectés.
- `decryption`: statut de tentative/succès du déchiffrement.
- `decrypted_keys` (si succès), avec `address_p2pkh`, `private_key_hex`, `private_key_wif` et `compressed`.

## Limites
- Le parsing Berkeley DB est volontairement "maison" et heuristique.
- Selon la version/structure du `wallet.dat`, certains enregistrements peuvent ne pas être reconstruits.
