# BTL1 Lab Writeup – Cerber Ransomware Investigation with Splunk

## Contexte

Dans ce lab, nous analysons une compromission sur le réseau de **WayneCorp Inc.** à l'aide de **Splunk** et du dataset **BOTSv1**. Un fichier suspect nommé `osk.exe` a été identifié, et notre mission est de confirmer sa nature malveillante, d'identifier le malware et de comprendre son comportement réseau.

**Outils utilisés :** Splunk, Sysmon (xmlwineventlog), Fortigate UTM, Suricata, VirusTotal, OSINT (Google)

---

## Q1 – OSINT : Qu'est-ce que osk.exe ?

Une recherche Google sur `osk.exe` révèle qu'il s'agit du binaire légitime de la fonctionnalité **Clavier Virtuel (On-Screen Keyboard)** de Windows.

**Réponse :** On-Screen Keyboard

---

## Q2 – Chemin légitime de osk.exe

Toujours via OSINT, le chemin attendu pour le binaire officiel est :

```
C:\Windows\System32\osk.exe
```

---

## Q3 – Nombre d'événements Sysmon contenant osk.exe

**Requête :**
```
index="botsv1" sourcetype=xmlwineventlog osk.exe
```

**Réponse :** 49 608 événements

---

## Q4 – Chemin complet du fichier suspect

En inspectant le champ `Image` dans les résultats, on constate que `osk.exe` ne se trouve **pas** dans `C:\Windows\System32\`, mais dans un chemin inhabituel :

```
C:\Users\Bob.Smith.WayneCorpInc\AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe
```

> ⚠️ Ce chemin dans `AppData\Roaming` avec un GUID aléatoire est un indicateur classique de malware cherchant à imiter un binaire légitime.

---

## Q5 – Système, IP et utilisateur concernés

À partir des champs des journaux Sysmon :

| Champ | Valeur |
|---|---|
| Hostname | `WAYNECORPINC\Bob.Smith` |
| Adresse IP interne | `192.168.250.100` |
| Compte utilisateur | `Bob.Smith.WayneCorpInc` |

---

## Q6 – Affinage de la requête & ports de destination

En ajoutant le champ `Image` à la requête pour cibler uniquement le fichier suspect :

```
index="botsv1" sourcetype=xmlwineventlog Image="C:\\Users\\Bob.Smith.WayneCorpInc\\AppData\\Roaming\\{35ACA89F-933F-6A5D-2776-A3589FB99832}\\osk.exe"
```

Les événements passent de 49 608 à **49 594**. En inspectant `DestinationPort`, deux ports sont observés :
- **80** (1 seul événement)
- **6892** (quasi totalité des événements)

> ⚠️ Un clavier virtuel n'a aucune raison de générer du trafic réseau. Le port 6892 (non standard) est très suspect.

---

## Q7 – Nombre d'adresses IP de destination uniques (port 6892)

```
index="botsv1" sourcetype=xmlwineventlog Image="C:\\Users\\Bob.Smith.WayneCorpInc\\AppData\\Roaming\\{35ACA89F-933F-6A5D-2776-A3589FB99832}\\osk.exe" DestinationPort=6892
| stats count by DestinationIP
```

**Réponse :** **16 384 adresses IP uniques** contactées en sortie.

---

## Q8 – Hash SHA256 du fichier suspect

Requête ciblant les événements Sysmon EventID 7 (ImageLoaded) :

```
index="botsv1" sourcetype=xmlwineventlog EventId=7 ImageLoaded=*osk.exe
```

Le champ `Hashes` contient la valeur SHA256 du fichier malveillant.

---

## Q9 – Identification du malware via VirusTotal

En soumettant le hash SHA256 sur [VirusTotal](https://www.virustotal.com), la page de détection affiche de nombreuses mentions du nom **Cerber**.

**Réponse :** Cerber

---

## Q10 – Logs Fortigate UTM & catégorie de malware

```
index="botsv1" sourcetype=fortigate_utm dest_port=6892
```

Les champs Fortigate confirment :
- `appcat` (catégorie) : **Botnet**
- `app` : Cerber
- `msg` : activité botnet Cerber détectée

**Réponse :** Botnet

---

## Q11 – Nom du malware selon Fortigate

**Réponse :** Cerber

---

## Q12 – Fonction principale du malware (OSINT)

Une recherche Google sur `Cerber malware` via des sources de référence (Malwarebytes, Kaspersky, etc.) confirme que Cerber est avant tout un **ransomware**, avec des capacités de botnet secondaires.

**Réponse :** Ransomware

---

## Q13 – Signature Suricata pour la connexion HTTP suspecte

**Étape 1** – Récupérer l'IP de destination de la connexion sur le port 80 :
```
index="botsv1" sourcetype=xmlwineventlog Image="...osk.exe" DestinationPort=80
```
→ IP de destination identifiée : `54.148.194.58`

**Étape 2** – Recherche dans les logs Suricata :
```
index="botsv1" sourcetype=suricata src_ip=192.168.250.100 dest_ip=54.148.194.58 dest_port=80 event_type=alert
```

Le champ `alert.signature` révèle une signature liée à une **recherche d'IP externe** – technique utilisée par les malwares pour identifier l'adresse IP publique de la machine compromise (reconnaissance réseau post-compromission).

---

## Conclusion

| Indicateur | Valeur |
|---|---|
| Fichier malveillant | `osk.exe` (faux binaire Windows) |
| Chemin | `AppData\Roaming\{GUID}\osk.exe` |
| Hôte compromis | `192.168.250.100` – Bob.Smith |
| Malware identifié | **Cerber** |
| Type | Ransomware / Botnet |
| IPs contactées | 16 384 adresses uniques (C2) |
| Port C2 | 6892 |

Ce lab illustre l'importance de combiner **OSINT**, **logs endpoint (Sysmon)**, **logs réseau (Fortigate, Suricata)** et **threat intelligence (VirusTotal)** pour mener une investigation complète et confirmer la présence d'un malware.
