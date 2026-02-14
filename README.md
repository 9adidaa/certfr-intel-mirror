# Documentation technique — CERT-FR (Avis & Alertes)

## Objectif
Cette documentation a pour objectif de fournir une référence technique sur les flux de veille du **CERT-FR (Centre gouvernemental de veille, d'alerte et de réponse aux attaques informatiques)**, opéré par l'ANSSI. Elle vise à permettre aux équipes techniques, CTI et SOC de comprendre, collecter et exploiter les **Avis de sécurité** et les **Alertes** pour contextualiser la menace et prioriser les actions de remédiation.

## Audience
- Analystes CTI (Cyber Threat Intelligence)
- Ingénieurs sécurité / SOC (Veille opérationnelle, Triage)
- Data Engineers / Data Analysts (Ingestion des flux RSS/CSAF, parsing, normalisation)
- Développeurs d'outils internes (Corrélation de vulnérabilités, tableaux de bord de conformité)
- Responsables Sécurité (RSSI) pour la priorisation basée sur le contexte national

## Portée
- Compréhension de la typologie ANSSI (Avis vs Alertes vs Bulletins)
- Méthodes d'accès aux données (Flux RSS, format CSAF 2.0)
- Structure des données (XML, JSON, Parsing HTML)
- Corrélation avec les données NVD (Mapping CVE)
- Bonnes pratiques d'ingestion et de cycle de vie (Mises à jour)

## Table des matières
1. [Introduction et contexte ANSSI](./01-introduction.md)
2. [Typologie : Avis vs Alertes](./02-typology-avis-alertes.md)
3. [Structure des données et Parsing](./03-data-structure-parsing.md)
4. [Accès aux données (RSS & CSAF)](./04-data-access.md)
5. [Cycle de vie et Mises à jour](./05-lifecycle.md)

---

<!-- STATUS:START -->
Last CI success: 2026-02-14 23:27 UTC

### Validation
| Check | Status |
|------|--------|
| Raw data present | ✅ |
| CVE index valid | ✅ |
| First-seen valid | ✅ |
| Tests executed | **11 passed** |

### Dataset size
- Advisories: **16478**
- Unique CVEs: **78942**

<!-- STATUS:END -->
