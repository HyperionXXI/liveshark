# Contrat de consommation du rapport JSON LiveShark

Ce document est un guide de compatibilite concis pour les consommateurs des rapports LiveShark.
Il ne remplace pas la specification ; la spec fait foi.

## Regles de compatibilite

- Les ajouts de champs sont non bloquants.
- Un consommateur DOIT ignorer les champs inconnus.
- Les champs optionnels sont omis lorsqu'ils ne sont pas calculables ; l'absence ne signifie pas zero.
- `report_version` designe le schema de base et ne change pas forcement pour les ajouts additifs.
- La perte est rapportee uniquement si des numeros de sequence existent (ex. sACN).

## Convention de fenetres (metriques)

Toutes les fenetres glissantes incluent les paquets dont l'horodatage est dans `[t - W, t]` (bornes incluses).

## Exemple minimal (presence vs absence)

```json
{
  "report_version": 1,
  "flows": [
    { "app_proto": "udp", "src": "10.0.0.1:1000", "dst": "10.0.0.2:2000" }
  ]
}
```

L'absence de `pps` ou `bps` ci-dessus signifie que les valeurs ne sont pas calculables, pas zero.

## Exemple (metriques optionnelles presentes)

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
