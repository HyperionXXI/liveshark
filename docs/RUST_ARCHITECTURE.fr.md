# Règles d'architecture Rust — traduction française (informative)

Ce document est la traduction française (informative) de `docs/RUST_ARCHITECTURE.md`.
En cas de divergence, la version anglaise fait foi.

## Portée

Ces règles s'appliquent à toutes les entrées externes : PCAP/PCAPNG, trames
réseau, fichiers, et charges utiles de protocoles.

## Modèle de décodage par couches (obligatoire)

Pour chaque protocole ou type de message, utiliser les modules suivants :

- `layout` : constantes pour les offsets, longueurs et plages du format
- `reader` : fonctions utilitaires sûres pour lire octets, entiers, tranches (« slices ») et chaînes
- `parser` : logique métier uniquement (conversion vers structures de domaine)
- `error` : type d'erreur dédié avec messages exploitables
- `tests` : tests unitaires ; tests golden quand la sortie alimente des rapports

Le parseur ne doit pas contenir d'accès bas niveau aux octets. Toute lecture
passe par `reader`.

## Pas de constantes magiques (obligatoire)

Aucun littéral numérique dans la logique de décodage. Tous les
offsets/longueurs/plages doivent être définis une seule fois dans `layout` en
`const` nommées en SCREAMING_SNAKE_CASE.

## Pas de panique sur données externes (obligatoire)

Pas de `unwrap`, `expect`, indexation directe, ni d'opération pouvant paniquer
sur des entrées invalides/courtes. Tout décodage retourne
`Result<_, ParseError>` (ou `Error`) et utilise un accès non paniquant (`.get`,
lecteurs sûrs).

## Fonctions utilitaires de lecture (obligatoire)

Centraliser les fonctions utilitaires dans `reader` :

- `read_u8(offset) -> Result<u8, _>`
- `read_u16_be(range) -> Result<u16, _>`
- `read_u16_le(range) -> Result<u16, _>`
- `read_u32_be(range) -> Result<u32, _>`
- `read_slice(range) -> Result<&[u8], _>`
- `read_ascii_string(range) -> Result<String, _>`

Les conventions de protocole (ex. « 0 signifie absent ») doivent être
encapsulées dans une fonction utilitaire (ex. `parse_optional_nonzero`), sans
répétition.

## Tests (obligatoire)

Chaque parseur a des tests unitaires. Si le parseur impacte la sortie des
rapports, ajouter des tests golden avec des entrées représentatives.

## Formatage (obligatoire)

Tout code Rust doit être formaté avec `cargo fmt` (rustfmt par défaut). Aucune
déviation manuelle de style.

## Liens de référence

- Rust Style Guide : https://doc.rust-lang.org/style-guide/
- Rust Book (gestion des erreurs, Result vs panic) : https://doc.rust-lang.org/book/ch09-00-error-handling.html
- RFC 1679 (panic-safe slicing) : https://rust-lang.github.io/rfcs/1679-panic-safe-slicing.html
- Rust std slice `.get` : https://doc.rust-lang.org/std/primitive.slice.html#method.get
- Séparation des préoccupations (SoC) : https://en.wikipedia.org/wiki/Separation_of_concerns
- DRY : https://en.wikipedia.org/wiki/Don%27t_repeat_yourself
