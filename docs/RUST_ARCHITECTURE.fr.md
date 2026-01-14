# Regles d'architecture Rust (Normatif)

Ce document est normatif pour le code Rust de LiveShark. Il definit la
structure et la methode de parsing des donnees externes. EN fait foi; FR est
une traduction.

## Portee

Ces regles s'appliquent a toutes les entrees externes: PCAP/PCAPNG, trames
reseau, fichiers, et charges utiles de protocoles.

## Modele par couches (obligatoire)

Pour chaque protocole ou type de message, utiliser les modules suivants:

- `layout`: constantes d'offsets, longueurs et ranges du format
- `reader`: helpers de lecture securises (octets, entiers, slices, chaines)
- `parser`: logique metier uniquement (conversion vers structures domaine)
- `error`: type d'erreur dedie, messages actionnables
- `tests`: tests unitaires; golden tests si pertinent

Le parseur ne doit pas contenir d'acces bas niveau aux octets. Tous les acces
passent par `reader`.

## Aucun "magic number" (obligatoire)

Aucune constante numerique brute dans le parsing. Tous les offsets/longueurs/
ranges sont definis une seule fois dans `layout` via des `const` nommes en
SCREAMING_SNAKE_CASE.

## Aucune panic sur donnees externes (obligatoire)

Pas de `unwrap`, `expect`, indexation directe, ni operation pouvant paniquer.
Tout parsing retourne `Result<_, ParseError>` (ou `Error` du module) et utilise
des acces non paniquants (`.get`, readers).

## Helpers reader (obligatoire)

Centraliser les helpers dans `reader`:

- `read_u8(offset) -> Result<u8, _>`
- `read_u16_be(range) -> Result<u16, _>`
- `read_u16_le(range) -> Result<u16, _>`
- `read_u32_be(range) -> Result<u32, _>`
- `read_slice(range) -> Result<&[u8], _>`
- `read_ascii_string(range) -> Result<String, _>`

Toute convention protocolaire (ex. "0 signifie absent") doit etre encapsulee
dans une fonction dediee (ex. `parse_optional_nonzero`), pas repetee.

## Tests (obligatoire)

Chaque parseur a des tests unitaires. Si le parseur impacte un rapport, ajouter
des tests golden avec des entrees representatives.

## Formatage (obligatoire)

Tout le code Rust doit etre formate via `cargo fmt` (rustfmt par defaut).
Aucune deviation manuelle.

## Liens de reference

- Rust Style Guide: https://doc.rust-lang.org/style-guide/
- Rust Book (gestion d'erreurs, Result vs panic): https://doc.rust-lang.org/book/ch09-00-error-handling.html
- RFC 1679 (panic-safe slicing): https://rust-lang.github.io/rfcs/1679-panic-safe-slicing.html
- Rust std slice `.get`: https://doc.rust-lang.org/std/primitive.slice.html#method.get
- Separation of Concerns (SoC): https://en.wikipedia.org/wiki/Separation_of_concerns
- DRY: https://en.wikipedia.org/wiki/Don%27t_repeat_yourself
