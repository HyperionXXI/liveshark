# Contrat de consommation du rapport JSON LiveShark

Ce document est un guide de compatibilité concis pour les consommateurs des rapports LiveShark.
Il ne remplace pas la spécification ; la spec fait foi.

## Règles de compatibilité

- Les ajouts de champs sont non bloquants.
- Un consommateur DOIT ignorer les champs inconnus.
- Les champs optionnels sont omis lorsqu'ils ne sont pas calculables ; l'absence ne signifie pas zéro.
- `report_version` désigne le schéma de base et ne change pas forcément pour les ajouts additifs.
- La perte est rapportée uniquement si des numéros de séquence existent (ex. sACN).

## Convention de fenêtres (métriques)

Toutes les fenêtres glissantes incluent les paquets dont l'horodatage est dans `[t - W, t]` (bornes incluses).

## Exemple minimal (présence vs absence)

```json
{
  "report_version": 1,
  "flows": [
    { "app_proto": "udp", "src": "10.0.0.1:1000", "dst": "10.0.0.2:2000" }
  ]
}
```

L'absence de `pps` ou `bps` ci-dessus signifie que les valeurs ne sont pas calculables, pas zéro.

## Exemple (métriques optionnelles présentes)

```json
{
  "flows": [
    {
      "app_proto": "udp",
      "src": "10.0.0.1:1000",
      "dst": "10.0.0.2:2000",
      "pps": 2.0,
      "bps": 20.0,
      "pps_peak_1s": 3,
      "bps_peak_1s": 30
    }
  ]
}
```
