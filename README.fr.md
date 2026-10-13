> [!WARNING]
> **Ceci est une traduction réalisée par IA, avec Claude.** Le README original fait près de cinq mille lignes et le traduire à la main n'est pas réaliste. La version canonique, et la seule que j'ai écrite, est la version espagnole : [README.md](README.md).

[🇪🇸 Español](README.md) · [🇬🇧 English](README.en.md) · [🇧🇬 Български](README.bg.md) · **🇫🇷 Français** · [🇩🇪 Deutsch](README.de.md)

# 1. Introduction

## 1.1 Objectif

Cher lecteur, je veux te transmettre de manière directe, personnelle et brève quel est l'objectif du projet.

Le projet est déjà assez long comme ça sans que même quelque chose d'aussi simple et personnel que cela me prenne beaucoup de temps à expliquer.

Ce projet est né avec deux objectifs :

- **D'une part, un objectif technique et professionnel :** concevoir, déployer et exploiter une infrastructure de honeypots capable d'attirer, de capturer et d'étudier l'activité d'attaquants réels, en appliquant des critères rigoureux de conception, de sécurité et de confinement. L'infrastructure en elle-même est quelque chose qui me passionne.

- **D'autre part, un objectif personnel :** servir de carte de visite de mes compétences dans le domaine de la cybersécurité défensive, à un moment où je cherche à évoluer professionnellement dans ce secteur.

Contrairement à un exercice de laboratoire, **ce travail fait face à des menaces réelles** et je suis pleinement conscient de la rigueur, des connaissances et de la philosophie qu'il faut y mettre, car l'enjeu pour moi n'est pas mince ; ici, il ne peut pas y avoir d'"erreurs humaines", et c'est aussi l'idée :

- **Démontrer** ma **capacité** à mener quelque chose du début à la fin, en respectant **une rigueur, un standard, sans erreurs humaines** ; en défense, les erreurs ne sont pas admises.

De même, exposer de façon contrôlée une machine à internet et observer qui tente de l'attaquer, avec quels outils et dans quels buts, **offre une perspective directe sur le paysage réel des menaces qu'on n'obtient pas dans des environnements simulés, avec le stress, la pression et la responsabilité que cela implique.**

Ce caractère réel est, pour moi, ce qui donne au projet sa valeur et son sens. Au-delà de l'exercice technique, le travail s'inscrit dans une motivation de fond : **contribuer, même modestement, à la défense contre la cybercriminalité**. La capture de malwares et d'indicateurs d'attaque, et leur signalement aux plateformes et autorités compétentes (si nécessaire), ne constituent pas seulement un exercice d'apprentissage, mais **une contribution réelle, aussi petite soit-elle, à l'effort collectif de défense** mené par des analystes et des équipes de sécurité du monde entier.

Quant aux ambitions, le projet visait très haut. Même si je sais pertinemment que la majeure partie de l'activité capturée sera du trafic automatisé et opportuniste, il a été conçu avec l'ambition de pouvoir détecter et documenter des menaces plus importantes (APT).

**Viser le maximum, tout en assumant avec réalisme ce qui est probable**, fait partie de l'approche avec laquelle il a été abordé.

Dans l'ensemble, ce projet entend démontrer des compétences pratiques en **déploiement sécurisé d'infrastructure, administration de systèmes et de réseaux, et cybersécurité défensive et renseignement sur les menaces**, tout en reflétant l'intérêt sincère et la vocation avec lesquels il a été réalisé.

<p align="center">J'espère que tu apprécieras, comprendras et surtout savoureras chaque mot et chaque action accomplis, autant que j'ai moi-même pris plaisir à le faire. Merci.</p>

## 1.2 Périmètre

Ce projet a pour objet la conception, le déploiement et l'exploitation d'une infrastructure de honeypots destinée à la capture et à l'étude de l'activité d'attaquants réels sur internet. Concrètement, le périmètre du travail comprend :

- Le déploiement de **deux honeypots complémentaires, Cowrie (pour SSH et Telnet) et Dionaea (pour de multiples protocoles réseau)**, sur un serveur privé virtuel (VPS), à l'aide de conteneurs Docker.
- La conception et la mise en œuvre des **mesures de sécurité et de confinement** nécessaires pour exposer la machine de manière responsable :
  - Configuration du pare-feu avec nftables.
  - Contrôle strict du trafic sortant (egress).
  - Durcissement des conteneurs.
- La personnalisation des honeypots pour accroître leur crédibilité auprès des attaquants.
- La collecte, l'observation et l'analyse de l'activité capturée (tentatives d'accès, commandes exécutées et malwares déposés).
- Le signalement des indicateurs obtenus à des plateformes de renseignement sur les menaces.

Sont **explicitement exclus du périmètre** de ce travail :

- **Toute utilisation offensive de l'infrastructure.** Le projet est strictement défensif et d'observation.
- **L'attribution des attaques** à des acteurs, groupes ou pays précis, conformément à l'approche de neutralité exposée dans la section consacrée aux considérations éthiques.
- **L'analyse forensique exhaustive ou la rétro-ingénierie approfondie** des malwares capturés, qui dépasse les objectifs de ce projet et pourrait constituer une piste de travail future.
- **Un déploiement de niveau entreprise ou de production.** Il s'agit d'un projet à caractère académique et de portfolio, bien que conçu avec des critères professionnels de rigueur et de sécurité.

## 1.3 Public visé

Ce travail **ne s'adresse pas aux débutants**.

Il suppose une base technique préalable, et s'adresse donc à des personnes ayant un profil de **niveau intermédiaire ou avancé** :

- Jeunes diplômés en ingénierie informatique ou en télécommunications
- Étudiants en master
- Professionnels et experts du domaine de la cybersécurité.

Il peut également intéresser :

- Les analystes en sécurité
- Le personnel du renseignement
- Les membres des forces de l'ordre ayant des compétences en cybersécurité.

Tout au long du document, on suppose que le lecteur est familiarisé avec les concepts de base des réseaux, des systèmes d'exploitation de type Linux et de l'administration de serveurs. Bien que beaucoup de ces concepts soient expliqués en détail au fil du projet (dans un but pédagogique), on ne part pas d'un niveau d'initiation absolue.

## 1.4 Avertissement éthique et juridique

Ce **projet s'inscrit strictement dans** le domaine de **la recherche défensive en cybersécurité**. Sa **finalité** est exclusivement **l'étude des techniques, outils et comportements employés par les attaquants**, dans le but de mieux comprendre les menaces et d'apprendre à s'en défendre. **Il ne s'agit en aucun cas d'attaquer qui que ce soit, de lui nuire ou d'exercer des représailles à son encontre.**

### Considérations sur les données et la vie privée

Pendant l'exploitation du honeypot, des données générées par les attaquants eux-mêmes sont collectées, dont les adresses IP d'origine.

Il convient de rappeler qu'**une** adresse **IP peut être considérée comme une donnée à caractère personnel au sens des textes suivants** :

- Le règlement général sur la protection des données (**RGPD**) de l'Union européenne.
- La loi organique 3/2018 sur la protection des données personnelles et la garantie des droits numériques (**LOPDGDD**), qui le complète en Espagne.

Dans le même sens, la Cour de justice de l'Union européenne, dans son arrêt Breyer (affaire C-582/14, du 19 octobre 2016), a jugé qu'**une adresse IP dynamique peut constituer une donnée à caractère personnel** lorsqu'il existe une possibilité raisonnable de la relier à une personne identifiable. Bien que l'arrêt ait été rendu sous l'empire de la directive 95/46/CE, antérieure au RGPD, son critère est cohérent avec celui que retient le règlement actuel dans son considérant 26.

Les réglementations sur la protection des données **protègent toute personne physique, y compris celles qui mènent des activités illicites**. Le RGPD ne protège pas les personnes morales, comme les entreprises.

Il ne serait pas correct non plus de se prévaloir de l'exception des activités strictement personnelles ou domestiques (article 2.2.c du RGPD) au motif qu'il s'agit d'un projet individuel. La Cour de justice interprète cette exception de façon restrictive : dans l'arrêt Ryneš (affaire C-212/13), elle a considéré qu'une caméra installée dans un logement qui filmait une partie de la voie publique ne relevait déjà plus de cette exception. **Un serveur exposé à internet, dont les données sont en outre partagées avec des plateformes publiques, entre à plus forte raison dans le champ du règlement.**

Le traitement de ces données dans le cadre de ce projet repose sur l'**intérêt légitime (article 6.1.f du RGPD)**, visant à garantir la sécurité des réseaux et de l'information, une finalité que le règlement lui-même reconnaît expressément comme intérêt légitime dans son considérant 49.

Toutefois, ce traitement est réalisé en appliquant les principes de **minimisation et de proportionnalité** : seul ce qui est nécessaire à l'analyse des menaces est collecté.

**Par prudence**, dans ce document, **les données suivantes ont été anonymisées ou masquées :**

- Adresses IP.
- Certains payloads.
- URL et adresses de serveurs de commande et de contrôle (C2).
- Les données propres à l'infrastructure du projet (l'IP publique du serveur, les identifiants et toute donnée qui pourrait compromettre sa sécurité).
- D'autres données sur l'attaquant.

Bien que ces données n'appartiennent pas aux catégories particulières que le RGPD considère comme sensibles (article 9 : santé, idéologie, origine ethnique, etc.), on a tout de même choisi de les anonymiser.

Le rapport d'analyse original, avec les données complètes, **est conservé chiffré en local sur mon propre ordinateur pendant un an au maximum** à compter de la clôture du projet, après quoi il sera supprimé. **Il n'est téléversé ni sur GitHub ni nulle part ailleurs sur internet**, car rien ne garantit que ce qui est publié soit effacé définitivement :

- Si quelqu'un le télécharge avant.
- L'historique des commits.
- WayBackMachine

Le choix d'anonymiser, et non de pseudonymiser, tient au fait que **le RGPD ne cesse de s'appliquer qu'aux données véritablement anonymisées**, qui par définition ne permettent d'identifier personne, alors que **les données pseudonymisées restent des données à caractère personnel** car, avec les informations supplémentaires adéquates, on peut remonter jusqu'à la personne.

Et enfin, concernant la "suppression dans un délai de 1 an au maximum" : tant que je conserve le rapport original, je peux annuler l'étiquetage. Selon une lecture stricte du considérant 26, qui tient compte des moyens du responsable du traitement lui-même, la version publiée serait anonyme pour n'importe quel lecteur, mais pseudonymisée pour moi jusqu'à ce que je supprime l'original. Il existe un débat juridique sur la question de savoir s'il faut se placer du point de vue de celui qui reçoit les données ou de n'importe qui. Mais **supprimer l'original à l'échéance du délai lève ce doute dans l'une comme dans l'autre interprétation.**

### Neutralité et contexte géopolitique

Tout au long du projet, le pays associé à chaque adresse IP est affiché **uniquement comme donnée technique, jamais comme attribution**. Les adresses IP, comme on l'a expliqué, ont été anonymisées au titre de la protection des données.

Le pays, en revanche, est conservé, car à lui seul il n'identifie personne, mais il convient de l'interpréter avec prudence : **il n'est pas possible d'attribuer avec une certitude totale une IP, un échantillon de malware ni aucune autre donnée à un pays précis.** L'adresse qui arrive au honeypot n'est que le dernier saut de la connexion, et derrière elle il peut y avoir un proxy, un VPN, le réseau Tor, un VPS loué dans un pays tiers, un serveur de commande et de contrôle (C2) ou, très souvent, un appareil IoT compromis qui fait partie d'un botnet et dont le propriétaire ne sait même pas qu'il est en train d'attaquer.

À tout cela s'ajoutent les **faux drapeaux**, c'est-à-dire des traces laissées délibérément (langue des chaînes de caractères, fuseaux horaires, infrastructure réutilisée) pour que l'attaque semble venir d'ailleurs.

Même **la géolocalisation d'une IP reflète l'endroit où la plage d'adresses est enregistrée, et non celui où se trouve la machine**, ni, encore moins, la personne qui la contrôle. De plus, comme nous le verrons plus loin, les plages IPv4 s'achètent, se vendent et se louent entre organisations de différents pays, de sorte qu'un bloc enregistré dans un pays peut être exploité dans un autre, ce qui brouille et complique encore davantage toute tentative d'attribution géographique.

**Par conséquent, qu'une connexion soit associée à un pays donné ne signifie pas que ce pays, ni aucune personne qui y réside, soit l'auteur de l'attaque.**

Il existe, en outre, une raison de contexte : étant donné le panorama géopolitique européen actuel, il a été jugé important que ce travail reste sur un plan technique et objectif, sans faire d'attributions ni alimenter aucune forme de dramatisation ou d'exploitation de la situation. **L'intérêt du projet réside dans le "comment" technique des attaques, pas dans le "qui"** ni dans leur origine géographique.

### Sur la sécurité du système lui-même

Il convient d'être honnête au sujet d'un principe fondamental de la discipline : **il n'existe pas de système sûr à 100 %**, et un honeypot, de par sa nature même de machine délibérément exposée, l'assume d'emblée.

Ce qui est possible, en revanche, et c'est l'approche adoptée dans ce travail, c'est d'appliquer une **conception extrêmement rigoureuse, professionnelle et dotée de multiples couches de confinement**, de sorte que le risque soit réduit à un minimum connu et maîtrisé.

### Autorisation du fournisseur et respect de ses conditions

Avant de lancer le projet, la première étape a été de **demander une autorisation expresse à l'entreprise qui fournit** le serveur privé virtuel (VPS).

Pour cela, un courriel a été envoyé, expliquant en toute transparence la nature du projet et les activités qui allaient être menées : le déploiement de honeypots pour capturer et étudier l'activité d'attaquants réels. **Le fournisseur a répondu en confirmant son accord avec l'activité.** Ce courriel n'est pas reproduit dans ce document par souci de confidentialité, mais il est conservé comme preuve que l'activité a été communiquée et autorisée à l'avance.

De même, les politiques et conditions d'utilisation du fournisseur ont été examinées une par une, afin de s'assurer que l'exploitation du honeypot reste dans les limites qu'il fixe.

**Il est vivement recommandé** à quiconque souhaite reproduire un projet de cette nature de **demander une autorisation préalable à son fournisseur et d'examiner ses conditions d'utilisation avant de déployer quoi que ce soit**. C'est une démarche simple qui évite des problèmes juridiques et de service, et c'est la manière responsable de procéder.

## 1.5 Risques

Tout honeypot comporte un risque inhérent : on expose délibérément une machine à des attaquants réels. Le danger principal n'est pas tant que l'attaquant "gagne" à l'intérieur de l'émulation, mais **que la machine compromise ou détournée devienne un outil pour attaquer des tiers**, avec tout le trafic sortant de l'IP publique du projet (avec les conséquences juridiques et de réputation qui en découlent, et une possible inscription sur des listes noires). Les risques identifiés et les mesures adoptées pour chacun d'eux sont détaillés ci-dessous.

### Risque 1 : abus de l'émulation de wget et curl pour l'amplification de DDoS (SSRF)

Le risque le plus documenté dans Cowrie est celui décrit dans la vulnérabilité **CVE-2025-34469**. Il s'agit d'une faille de type SSRF (Server-Side Request Forgery) dans l'émulation des commandes wget et curl : en mode shell émulé (celui utilisé par défaut), ces émulations effectuent de vraies requêtes HTTP vers la destination indiquée par l'attaquant. Faute de limite de débit sur ces requêtes, un attaquant non authentifié pouvait invoquer ces commandes à répétition pour générer un trafic HTTP illimité contre une victime, **en utilisant le honeypot comme nœud d'amplification de déni de service** et en masquant sa propre IP derrière celle du honeypot.

**Comment ce risque est atténué dans ce projet :**

- La version de Cowrie déployée (3.0.10) est postérieure à la 2.9.0, qui est celle qui corrige officiellement cette vulnérabilité. Par conséquent, **le déploiement n'est pas vulnérable à ce CVE précis**.

- De plus, et indépendamment du correctif, le pare-feu de sortie (egress) impose une limite de débit stricte aux connexions sortantes des conteneurs (voir la section sur l'egress). Cela signifie que, même s'il existait une faille similaire, la machine ne pourrait pas générer le volume de trafic nécessaire pour amplifier une attaque. **C'est une défense en profondeur : on ne dépend pas seulement du fait que le logiciel soit corrigé.**

### Risque 2 : évasion de l'émulation vers le système réel

Bien que Cowrie simule un faux système de fichiers et un faux shell, on ne peut pas totalement exclure qu'il existe une vulnérabilité permettant à un attaquant de s'échapper de l'émulation et d'exécuter du code sur le système réel. **C'est un risque faible, mais pas nul.**

**Comment ce risque est atténué dans ce projet :**

- Cowrie s'exécute dans un **conteneur Docker dédié**, et non directement sur le système hôte.
- Le **conteneur est durci** (no-new-privileges, limites de mémoire, de CPU et de nombre de processus), de sorte qu'une éventuelle évasion se heurterait à un environnement restreint.
- Le pare-feu de sortie **bloque l'accès aux réseaux internes et à l'infrastructure elle-même**, empêchant le mouvement latéral (pivot) même en cas d'évasion.

### Risque 3 : usage abusif du mode proxy (haute interaction)

Cowrie dispose d'un mode à haute interaction (proxy) qui redirige le trafic SSH vers un système réel. S'il était activé sans contrôle, il pourrait servir à atteindre d'autres systèmes.

**Comment ce risque est atténué dans ce projet :**

- **Le déploiement utilise le mode shell émulé (backend = shell), et non le mode proxy.** Cela a été vérifié dans les journaux de démarrage de Cowrie. Il n'y a aucun système réel derrière vers lequel rediriger.

### Risque 4 : l'attaquant se rend compte qu'il est dans un honeypot

Un attaquant qui détecte qu'il a affaire à un honeypot peut abandonner, fausser son comportement ou, dans le pire des cas, exercer des représailles. Ce n'est pas un risque de dommage pour des tiers, mais **cela compromet bel et bien l'objectif du projet (recueillir du renseignement)**.

**Comment ce risque est atténué dans ce projet :**

- **Personnalisation de Cowrie** pour accroître sa crédibilité (nom d'hôte, données système cohérentes avec une vraie Debian, utilisateurs et système de fichiers vraisemblables), détaillée dans la section correspondante.

Et une dernière chose très importante **à mentionner à propos du risque 4 :**

**Objectivement, il est presque impossible que la machine Cowrie et Dionaea ne ressemble pas à un honeypot.**

Pourquoi ?

1. Ce sont des honeypots à moyenne et basse interaction respectivement, ils n'ont ni disque dur ni aucun stockage persistant : si tu te connectes et crées un fichier, il est effacé quand tu te déconnectes.

   Et ça le trahit.

2. Il y a des scripts, des structures de contrôle ou l'utilisation de "python3" véritablement impossibles à reproduire.

   Et ça le trahit.

3. Des commandes qui peuvent casser la simulation. Des téléchargements de programmes comme "nmap" ou "masscan", ou, chose moins fréquente, des mises à jour ou la mise à jour de la machine. Est-il vraiment réaliste de programmer la possibilité de télécharger n'importe quel programme ?

   Et ça le trahit.

**Rien qu'avec ces 3 raisons, j'espère que tu comprends qu'il est presque impossible de recréer quelque chose de réaliste à 100 %.** La solution à cela, que nous n'allons pas utiliser, est un honeypot à haute interaction, une vraie machine.

# 2. Architecture, infrastructure et concepts.

Les explications détaillées se trouvent dans le document principal. Ce dépôt
couvre la section 3, Procédures.

## 2.1 Architecture

![Architecture](IMG/arquitectura.png)

## 2.2 Infrastructure

|  | VPS |
| ---: | :---   |
| CPU | 1 core |
| RAM | 2GB  |
| STOCKAGE | 40GB (NVME) |
| IP('s) | 2 |
| BANDE PASSANTE | 4TB/mois |
| OS | Debian 13, Trixie |
| HoneyPot | Cowrie + Dionaea |

# 3 Procédures

Nous commencerons en suivant non seulement un ordre logique, mais aussi un ordre de priorité selon l'importance. La procédure serait la même pour presque n'importe quelle machine de presque n'importe quel fournisseur.

## 3.1 La seule chose qui N'EST PAS du copier-coller.

Ce guide est pensé pour copier-coller des commandes sans trop réfléchir. <br>Il contient des explications là où elles sont nécessaires, et à certains moments tu devras mettre des choses à toi : tes IP, tes ports, tes clés.

Voici les neuf fichiers que tu devras modifier plus loin :

| Fichier | Section | Pourquoi on ne peut pas le copier |
|---|---|---|
| `/etc/hosts` | 3.2.1 | Il contient le nom de la machine |
| `/etc/netplan/50-cloud-init.yaml` | 3.2.7 | Il contient la deuxième IP publique |
| `/etc/ssh/sshd_config.d/99-hardening.conf` | 3.2.5, 3.2.6 | Port d'administration et utilisateur autorisé |
| `/etc/nftables.conf` (parties 1 et 2) | 3.3 | Elles s'appliquent **avant** de téléverser le dépôt : à ce moment-là, il n'y a rien à copier |
| `/etc/nftables.conf` (parties 3 et 4) | 3.3.2, 3.8.2 | Elles pourraient se copier ; on les colle exprès, parce que le pare-feu se relit ligne par ligne et le coller oblige à le regarder |
| `/opt/dirtyland/docker-compose.yml` | 3.4 | Il contient tes deux IP publiques dans le `ports:` |
| `/opt/dirtyland/cowrie/etc/cowrie.cfg` et `userdb.txt` | 3.4 | La légende et les mots de passe du leurre |
| `/opt/dirtyland/Telegram Reports/telegram.cfg` | 3.4.2.7 | Tes deux tokens de bot et ton chat |
| `/opt/dirtyland/platform-reporter/config.ini` | 3.5.5, 3.8.1 | Les clés d'API des cinq plateformes |

Tout au long du guide, tu verras `[IP VPS]`, qui est celle de Cowrie, et `[IP VPS 2]`, qui est celle de Dionaea. Tout le reste se colle tel quel.

## 3.2 Après la location du VPS (après le paiement)

### 3.2.1 À faire immédiatement.

On accédera à la machine VPS par SSH.<br>
Lors de l'achat, on nous demandera d'indiquer la clé publique que nous générerons sur notre machine locale. Il est important que la clé privée ait un mot de passe, une "passphrase".

Dans mon cas, sous Linux Mint :

```bash
ssh-keygen -t ed25519 -C "admin-honeypot"
```

On affiche la clé publique, on la colle sur la page du fournisseur du VPS et on confirme. 

```bash
cat ~/.ssh/honeypot_vps.pub
```

Grâce à cela, nous pourrons maintenant accéder à la machine.

> [!IMPORTANT]
> Si nous supprimons la clé privée que nous avons en local, nous perdons l'accès ; donc, si nous voulions la changer, il faudrait d'abord créer une autre clé privée, puis retirer la première.

```bash
ssh -i ~/.ssh/honeypot_vps root@[IP]
```

Changer le mot de passe de l'utilisateur qu'on nous a fourni. Que ce soit "root", "admin" ou un autre. D'ailleurs, on aurait dû nous envoyer un e-mail prévenant que le mot de passe doit être changé le plus tôt possible.

Une fois connectés en ssh :

```bash
passwd
```

Cette étape est la plus urgente, contrairement aux suivantes. Nous pouvons aussi en profiter maintenant pour changer le hostname si nécessaire :

```bash
sudo hostnamectl set-hostname hostname
```

```bash
sudo nano /etc/hosts
```
Et à l'intérieur, sur la même ligne que 127.0.0.1, tu mets à côté le "hostname".

**Dans mon cas, il me prévient que cela NE suffira PAS à lui seul. Si ton cas N'EST PAS comme le mien, saute cette étape et passe au 3.2.2. Sinon, modifie le fichier, mais nous allons modifier aussi celui de cloud-init (le modèle) ; l'avertissement est celui-ci :**

<pre>
    GNU nano 8.4                       /etc/hosts
# Your system has configured 'manage_etc_hosts' as True.
# As a result, if you wish for changes to this file to persist
# then you will need to either
# a.) make changes to the master file in /etc/cloud/templates/hosts.debian.tmpl
# b.) change or remove the value of 'manage_etc_hosts' in
#     /etc/cloud/cloud.cfg or cloud-config from user-data
#
</pre>

```bash
sudo cp -a /etc/cloud/cloud.cfg /etc/cloud/cloud.cfg.bak-$(date +%F)
```

```bash
sudo tee /etc/cloud/cloud.cfg.d/99-dirtyland-hostname.cfg > /dev/null <<'EOF'
preserve_hostname: true
manage_etc_hosts: false
EOF
```

```bash
sudo sed -i 's/^\( *\)- update_etc_hosts$/\1# - update_etc_hosts/' /etc/cloud/cloud.cfg
```

```bash
grep -n "update_etc_hosts" /etc/cloud/cloud.cfg
```

On redémarre, ou `exec bash`, ou on ouvre un nouveau terminal :

```bash
hostnamectl && cat /etc/hosts
```

### 3.2.2 Vérifications sur notre produit.

L'architecture du VPS prévoit <b>deux IP publiques sur la même machine</b> : 
- Une pour le leurre Linux (Cowrie, SSH/Telnet)
- et une autre, séparée, pour le leurre Windows (Dionaea, SMB/RPC/MSSQL).

La raison d'utiliser deux adresses IP est qu'il n'a aucun sens que Windows et Linux partagent la même IP. Si Dionaea simulait un environnement Windows et un autre basé sur Debian 13 avec une seule adresse IP, cela révélerait que le VPS est un honeypot.

C'est pourquoi, en souscrivant le VPS, nous demandons (ou ajoutons) une deuxième IP publique.

Pour chacune des deux IP, nous vérifions :

- Que le serveur est géographiquement situé à l'endroit demandé.
- Que l'IP a une bonne réputation. Sinon, nous demandons un remboursement.
  - Pour cela, nous chercherons sur ces pages :
    - https://www.virustotal.com/gui/home/url
    - https://www.abuseipdb.com/
    - https://viz.greynoise.io/
    - https://www.shodan.io/
    - https://www.ipvoid.com/

- Qu'aucun nom de domaine de l'ancien propriétaire ne soit associé à cette IP (enregistrement PTR). Par hygiène et par éthique envers la personne qui a utilisé cette IP auparavant.

![](IMG/Pasted%20image%2020261009175859.png)
![](IMG/Pasted%20image%2020261009175950.png)
- Vérifier les ports et ce qui est exposé sur la machine VPS.

<pre>
root@hostname:~# ss -tulnp
Netid   State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port   Process                                                                         
udp     UNCONN   0        0             127.0.0.54:53            0.0.0.0:*       users:(("systemd-resolve",pid=4099,fd=22))                                     
udp     UNCONN   0        0          127.0.0.53%lo:53            0.0.0.0:*       users:(("systemd-resolve",pid=4099,fd=20))                                     
udp     UNCONN   0        0                0.0.0.0:5355          0.0.0.0:*       users:(("systemd-resolve",pid=4099,fd=11))                                     
udp     UNCONN   0        0                   [::]:5355             [::]:*       users:(("systemd-resolve",pid=4099,fd=13))                                     
tcp     LISTEN   0        128              0.0.0.0:22            0.0.0.0:*       users:(("sshd",pid=6944,fd=6))                                                 
tcp     LISTEN   0        4096          127.0.0.54:53            0.0.0.0:*       users:(("systemd-resolve",pid=4099,fd=23))                                     
tcp     LISTEN   0        4096       127.0.0.53%lo:53            0.0.0.0:*       users:(("systemd-resolve",pid=4099,fd=21))                                     
tcp     LISTEN   0        4096             0.0.0.0:5355          0.0.0.0:*       users:(("systemd-resolve",pid=4099,fd=12))                                     
tcp     LISTEN   0        128                 [::]:22               [::]:*       users:(("sshd",pid=6944,fd=7))                                                 
tcp     LISTEN   0        4096                [::]:5355             [::]:*       users:(("systemd-resolve",pid=4099,fd=14))                                     
</pre>

**Regarde la colonne Local Address.** Si elle commence par `127.` ou `[::1]`, le port n'écoute qu'à l'intérieur de la machine et peu importe ce que c'est. Ce qui doit inquiéter, c'est ce qui écoute sur `0.0.0.0`, sur `[::]` ou sur une IP publique.

| Port | Ce que c'est | Exposé ? |
|---|---|---|
| 53 sur `127.0.0.53` et `.54` | Le résolveur DNS de systemd | Non, loopback |
| 25 | `exim4`, le courrier local fourni avec Debian | Non, loopback |
| 22 sur `0.0.0.0` | Ton SSH. La seule chose ouverte pour l'instant, et celle que tu vas durcir | Oui |
| 5355 sur `0.0.0.0` | LLMNR, lui aussi de systemd-resolved | Oui, mais nftables avec `policy drop` le bloque |

### 3.2.3 Prérequis avant le durcissement et la configuration de l'hôte.

- Souscrire à Mullvad (dans mon cas) et vérifier qu'il fonctionne. Ce que le pare-feu laissera entrer en SSH, ce n'est pas "le VPN", mais les **IP de sortie de ses proxys SOCKS5**.
  Si le VPN fonctionne mais que la connexion ne passe pas par le proxy, la machine te refusera (3.2.6.3).

> [!IMPORTANT]
> Jamais une seule de ces IP : les relais tombent ou sont renumérotés, et alors ton propre pare-feu te laisse dehors. Ici, il y en a trois, dans des pays différents.

- Et pour ne pas perdre l'accès à la machine, il faut que la page web du fournisseur du VPS propose un panneau d'accès web pour configurer la machine depuis là si l'accès SSH ou quoi que ce soit d'autre échoue.

> [!TIP]
> Regarde-le **avant** d'en avoir besoin. Beaucoup le servent avec un vieux `noVNC` **sans presse-papiers**, et là tout se tape à la main. Que le mot de passe de `root` soit long, mais tapable.

### 3.2.4 Principe du moindre privilège.

Nous allons créer un nouvel utilisateur pour ne pas utiliser root en permanence ni nous connecter en "root" par SSH. 
<p>On met à jour la machine :</p>

```bash
apt update && apt upgrade -y
```

Et on crée un nouvel utilisateur. Le nom n'a aucune importance, car rien du VPS ne sera exposé.

```bash
adduser --gecos "" user
```

On lui donne les droits "sudo" :

```bash
usermod -aG sudo user
```
Si sudo n'existe pas, on l'installe : `apt install sudo`.

```bash
groups user
```
Et quelque chose comme ceci doit apparaître :

`[NOMBRE USUARIO]: [NOMBRE USUARIO] sudo users`

### 3.2.5 Accès du nouvel utilisateur par SSH.

> [!IMPORTANT]
> **Toujours en root :**

```bash
mkdir -p /home/user/.ssh
```
Les clés que j'ai générées sur mon propre ordinateur pour accéder à root seront copiées pour accéder au nouvel utilisateur :

```bash
cp /root/.ssh/authorized_keys /home/user/.ssh/authorized_keys
```

Comme nous travaillons en root, les fichiers ont été créés par "root" ; nous allons donc changer le propriétaire pour le nouvel utilisateur et laisser les permissions qu'exige SSH. Les trois vont enchaînés avec `&&`, en un seul collage :

```bash
chown -R user:user /home/user/.ssh/ && chmod 700 /home/user/.ssh && chmod 600 /home/user/.ssh/authorized_keys
```

> [!NOTE]
> <b>`&&` et non `;`.</b> Avec `&&`, chaque commande ne s'exécute <b>que si la précédente s'est bien terminée</b> Si quelque chose échoue, la chaîne s'arrête net et l'erreur est visible.

Si tu veux vérifier que tout est OK :

```bash
ls -lah /home/user/.ssh/
```
Cela doit afficher :
- `drwx------` .
- `drwx------` ..
- `-rw-------` authorized_keys

Et si tu veux vérifier pour de bon que cela fonctionne, essaie de te connecter en ssh avec le nouvel utilisateur. Par précaution, on ouvre un autre terminal sans fermer celui-ci et on exécute :

```bash
ssh -i ~/.ssh/claveprivada user@[IP]
```

```bash
whoami && echo " " && groups && echo " " && id && echo " " && sudo whoami
```

Cela affichera : <br>
`user` <br>
`user sudo user` <br>
`uid=1000(user) gid=1000(user) groups=1000(user),27(sudo),100(users)` <br>
`root`

### 3.2.6 Sécuriser SSH.

Dans cette nouvelle section :
- Ouvre un nouveau terminal, CTRL + SHIFT + T, quel que soit le système d'exploitation.
- On décidera quel port, autre que le 22, nous utiliserons pour nous connecter en SSH.
	- On cherche à ce que ce ne soit pas le 22, pour que les bots ne l'attaquent pas, car c'est celui qu'ils visent par défaut.
	- Et qu'il ne soit pas non plus l'un des évidents : un `2222`, un `4444` ou un `4445` sont aussi scannés que le 22 lui-même et ne t'épargnent rien.
- Connaître les noms des serveurs proxy que nous utiliserons pour accéder en SSH exclusivement depuis ces IP et d'aucune autre manière.

Sur l'approche de la sécurité opérationnelle, mieux vaut la préciser pour ne pas se tromper d'objectif : 
- On ne cherche pas ici un OPSEC sophistiqué, du genre payer le VPN en liquide par courrier pour ne laisser aucune trace financière. Ce n'est pas nécessaire, car cette trace ne serait visible que par des banques ou des gouvernements, et le modèle de menace de ce projet est autre et bien plus restreint. 
- De Mullvad, on attend une chose précise : qu'il cache l'IP réelle en faisant lui-même les requêtes. Ce qu'il faut en revanche bien garder, c'est le numéro de compte Mullvad, car il sert à la fois d'identifiant et de mot de passe.

#### 3.2.6.1 Si tu vas te connecter depuis Linux.

> [!IMPORTANT]
> **Sur notre machine hôte, PAS SUR LE VPS.**

Comme nous l'avons dit, nous allons nous connecter via un proxy SOCKS ; la première chose à connaître, ce sont donc les IP et les serveurs eux-mêmes.

Mullvad publie la liste complète dans son API. Ceci extrait les relais qui ont SOCKS5 **et sont actifs**, avec leur pays et leur ville :

```bash
curl -s https://api.mullvad.net/www/relays/all/ | jq -r '.[] | select(.socks_name and .active) | [(.socks_name | sub("\\.relays\\.mullvad\\.net$";"")), .country_name, .city_name] | @tsv' | sort | awk -F'\t' '{printf "%-26s %-20s %s\n", $1, $2, $3}'
```

Il y en a plus de cinq cents, donc le plus courant est de filtrer. Le pays est en anglais, donc l'Espagne, c'est `spain` :

```bash
curl -s https://api.mullvad.net/www/relays/all/ | jq -r '.[] | select(.socks_name and .active) | [(.socks_name | sub("\\.relays\\.mullvad\\.net$";"")), .country_name, .city_name] | @tsv' | grep -i spain | awk -F'\t' '{printf "%-26s %-20s %s\n", $1, $2, $3}'
```

Si tu n'as pas `jq`, `sudo apt install -y jq`.

**Choisis-en trois, dans des pays différents :** un principal et deux de secours. Le nom dont tu as besoin est celui de gauche, sans le suffixe `.relays.mullvad.net`.

Maintenant, le fichier. La configuration n'est pas écrite ici : elle est dans le dépôt, dans **[Local SSH/For Linux/config](Local%20SSH/For%20Linux/config)**. Ouvre-le, copie-le en entier et colle-le à la fin de ton `~/.ssh/config`.

En gardant d'abord une copie de celui qui existait, et en l'ouvrant pour coller :

```bash
cp ~/.ssh/config ~/.ssh/config.bak 2>/dev/null; nano ~/.ssh/config
```

Une fois collé, on remplace les emplacements qui sont entre `< >` :

| Emplacement | Par |
|---|---|
| `<IP a la que te vas a conectar>` | l'IP publique de ton VPS |
| `<Futuro puerto SSH>` | le port que tu mettras au 3.2.6.3 |
| `<proxy principal>` | le relais que tu as choisi plus haut, sans le `.relays.mullvad.net` |
| `<proxy-respaldo-1>` et `<proxy-respaldo-2>` | les deux autres |
| `<pais-1>` et `<pais-2>` | le nom que tu veux donner aux deux alias de secours (`se`, `fr`, `jp`...) |

Et on lui laisse les permissions qu'exige SSH :

```bash
chmod 600 ~/.ssh/config
```

**On vérifie (facultatif)**. Ceci lit dans le fichier lui-même les alias que tu as mis, donc cela fonctionne quel que soit leur nom :

```bash
for h in $(awk '/^Host dirtyland/{print $2}' ~/.ssh/config); do
  echo "=== $h ==="
  ssh -G $h | grep -Ei '^(hostname|port|user|identityfile|proxycommand)'
done
```

#### 3.2.6.2 Si ton ordinateur est sous Windows.

> [!IMPORTANT]
> **Sur notre machine hôte, PAS SUR LE VPS. Si tu as fait le 3.2.6.1, ne fais pas celui-ci.**

Écrit sous Windows 11 Pro.<br>
Le client OpenSSH est fourni d'origine depuis Windows 10, il lit le même `~/.ssh/config` et inclut `ssh`, `scp` et `ssh-add` ; il n'y a rien à installer.

**1. Choisir les trois proxys.**

La même liste Mullvad que sous Linux, ici avec PowerShell. Il en sort les relais avec SOCKS5 actifs, triés par pays :

```powershell
(Invoke-RestMethod https://api.mullvad.net/www/relays/all/) | Where-Object { $_.socks_name -and $_.active } | Sort-Object country_name, city_name | Format-Table @{n='Proxy';e={$_.socks_name -replace '\.relays\.mullvad\.net$',''};width=26}, @{n='Pais';e={$_.country_name};width=20}, @{n='Ciudad';e={$_.city_name};width=22}
```

Il y en a plus de cinq cents. Pour filtrer par pays, on ajoute le filtre :

```powershell
(Invoke-RestMethod https://api.mullvad.net/www/relays/all/) | Where-Object { $_.socks_name -and $_.active -and $_.country_name -eq 'Spain' } | Format-Table @{n='Proxy';e={$_.socks_name -replace '\.relays\.mullvad\.net$',''};width=26}, @{n='Ciudad';e={$_.city_name};width=22}
```
Comme on peut le voir, cela nous montre les serveurs d'Espagne, Spain. Si nous en voulions d'un autre pays, il suffirait d'enlever Spain et de mettre le pays en question en anglais.

**Choisis-en trois, dans des pays différents :** un principal et deux de secours. Le nom dont tu as besoin est celui de la colonne `Proxy`, sans le suffixe `.relays.mullvad.net`.

**2. Vérifier que tu as `connect.exe`.**

Le `ProxyCommand` de Linux utilise `nc -X 5` pour parler SOCKS5 avec le relais, et Windows n'inclut pas netcat. Il est remplacé par `connect.exe`, fourni avec **Git pour Windows** (si tu as cloné ce dépôt, tu l'as) :

```powershell
Test-Path "C:\Program Files\Git\mingw64\bin\connect.exe"
```

Cela doit répondre `True`. <br>
Si cela répond `False`, installe Git pour Windows et refais la vérification :

```powershell
winget install --id Git.Git -e
```

**3. Créer le dossier `.ssh` et y placer la clé privée.**

```powershell
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.ssh" | Out-Null
```

Copie-y `honeypot_vps` (le fichier est le même que sous Linux, il se copie tel quel) et vérifie qu'il est au bon endroit :

```powershell
Test-Path "$env:USERPROFILE\.ssh\honeypot_vps"
```

**4. Écrire le fichier `%USERPROFILE%\.ssh\config`.**

C'est le fichier qu'il faut modifier. La configuration n'est pas écrite ici : elle est dans le dépôt, dans **[Local SSH/For Windows/config](Local%20SSH/For%20Windows/config)**. C'est la même que celle de Linux, sauf la ligne du `ProxyCommand`, qui appelle `connect.exe` au lieu de netcat. Ouvre-le, copie-le en entier et colle-le à la fin de ton `config`.

En gardant d'abord une copie de celui qui existait, et en l'ouvrant pour coller (s'il n'existe pas, le Bloc-notes te propose de le créer) :

```powershell
if (Test-Path "$env:USERPROFILE\.ssh\config") { Copy-Item "$env:USERPROFILE\.ssh\config" "$env:USERPROFILE\.ssh\config.bak" -Force }
notepad "$env:USERPROFILE\.ssh\config"
```

Une fois collé, on remplace les emplacements qui sont entre `< >` :

| Emplacement | Par |
|---|---|
| `<IP a la que te vas a conectar>` | l'IP publique de ton VPS |
| `<Futuro puerto SSH>` | le port que tu mettras au 3.2.6.3 |
| `<proxy principal>` | le relais que tu as choisi plus haut, sans le `.relays.mullvad.net` |
| `<proxy-respaldo-1>` et `<proxy-respaldo-2>` | les deux autres |
| `<pais-1>` et `<pais-2>` | le nom que tu veux donner aux deux alias de secours (`se`, `fr`, `jp`...) |

> [!IMPORTANT]
> **À l'enregistrement, le fichier s'appelle `config`, sans extension.** Le Bloc-notes ajoute `.txt` de lui-même si tu ne choisis pas "Tous les fichiers" dans la liste déroulante du type. Un `config.txt`, personne ne le lit, et le symptôme est que `ssh dirtyland` répond qu'il ne connaît pas cet hôte.
>
> Et dans "Encodage", **UTF-8**, pas "UTF-8 avec BOM" : ces trois octets invisibles au début suffisent pour qu'OpenSSH ne comprenne pas la première ligne. Le modèle est en ASCII pur exprès, c'est pour cela que ses commentaires sont sans accents, donc n'importe laquelle des deux options sans BOM convient.

**5. Permissions de la clé privée.**

Sous Windows, les permissions sont des ACL, pas des bits Unix, donc il n'y a pas de `chmod 600` ici. OpenSSH refuse d'utiliser une clé privée que d'autres peuvent lire, et sans ceci il échoue avec `UNPROTECTED PRIVATE KEY FILE` :

```powershell
icacls "$env:USERPROFILE\.ssh\honeypot_vps" /inheritance:r /grant:r "$($env:USERNAME):(R)"
```

`/inheritance:r` coupe les permissions héritées du dossier, c'est de là que vient le problème, et `/grant:r` ne laisse que ton utilisateur, en lecture. Sans le premier, le second ne règle rien : les permissions héritées sont toujours là.

**6. Activer l'agent SSH.**

La clé a un mot de passe. Sous Linux, l'agent tourne déjà ; sous Windows, le service existe mais **est désactivé par défaut**, donc `ssh dirtyland` te le demanderait à chaque fois. Dans un PowerShell **en tant qu'administrateur** :

```powershell
Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent
```

S'il répond `Acceso denegado`, c'est que ce PowerShell n'était pas administrateur. Vérifie-le avant de t'acharner, car c'était peut-être déjà fait :

```powershell
Get-Service ssh-agent | Select-Object Name, Status, StartType
```

S'il affiche `Running` et `Automatic`, l'erreur n'avait pas d'importance : c'était déjà comme il faut.

Ensuite, dans un PowerShell normal, on ajoute la clé ; le mot de passe se tape ici, une seule fois :

```powershell
ssh-add "$env:USERPROFILE\.ssh\honeypot_vps"
```

**7. Vérifier.**

Ceci lit dans le fichier lui-même les alias que tu as mis, donc cela fonctionne quel que soit leur nom. Il ne se connecte à rien : il montre seulement ce que `ssh` a compris.

```powershell
$alias = Select-String -Path "$env:USERPROFILE\.ssh\config" -Pattern '^Host (dirtyland\S*)' | ForEach-Object { $_.Matches[0].Groups[1].Value } | Select-Object -Unique
foreach ($h in $alias) { "=== $h ==="; ssh -G $h | Select-String -Pattern '^(hostname|port|user|identityfile|proxycommand)' }
```

#### 3.2.6.3 Retour à la sécurisation de SSH.

> [!IMPORTANT]
> **DANS LE VPS, avec le nouvel utilisateur, PAS en root.**

Le durcissement va dans un fichier à part dans `sshd_config.d/`, et non en modifiant le `sshd_config` principal, par souci d'organisation : il reste identifié et facile à trouver au lieu d'être mélangé à ce qu'apportait l'image du fournisseur.

```bash
sudo nano /etc/ssh/sshd_config.d/99-hardening.conf
```

Il sera vide ; on y ajoute :

```conf
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowUsers user
MaxAuthTries 3
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
```
La première configuration de SSH, en gros :
- On cherche à interdire l'accès en root par SSH.
- Seul le nouvel "user" créé le pourra.
- Interdit d'utiliser un mot de passe pour s'authentifier, seulement la clé privée.
- Ici, le port reste le 22 pour se connecter ; on le changera plus tard.

On vérifie la syntaxe :

```bash
sudo sshd -t
```

```bash
sudo systemctl reload ssh
```

Une fois que cela s'est appliqué après le redémarrage, nous allons imposer que l'accès se fasse exclusivement via les proxys SOCKS5 de Mullvad. Par conséquent :
- Nous devons connaître les IP que nous utiliserons, 2 au minimum et 3 au maximum.
- Par quel port SSH nous nous connecterons à l'avenir ; dans mon cas, j'ai choisi le `56769`.

**Et ces IP ne sont pas celles que donne l'API de Mullvad.** `ipv4_addr_in` est celle d'**entrée** du relais ; celle que ton VPS verra arriver, et donc celle qu'il faut autoriser, est celle de **sortie**. On la demande à travers le proxy lui-même, **depuis ton ordinateur et avec le tunnel monté**. 

<b>Sous Linux :</b>

```bash
curl -sS -x socks5h://<proxy>.relays.mullvad.net:1080 https://am.i.mullvad.net/ip
```

<b>Sous Windows, la même chose, avec `curl.exe` :</b>

```bash
curl.exe -sS -x socks5h://<proxy>.relays.mullvad.net:1080 https://am.i.mullvad.net/ip
```

Une fois pour chacun des trois proxys, en changeant le nom. Ces trois adresses sont celles qui vont dans les règles ci-dessous. Et regarde-les de nouveau si un jour tu perds l'accès, car **Mullvad les renumérote**.

Si, au lieu d'une IP, tu obtiens `curl: (28) Connection timed out`, ce relais est hors service. Ce n'est pas de ton fait et cela ne s'arrange pas en attendant : choisis-en un autre et refais la liste, car la liste ci-dessus ne montre déjà que les relais actifs. Le `-sS` est là précisément pour cela : il fait taire le compteur de progression mais **pas** les erreurs, car avec `-s` seul, un relais tombé n'affiche rien et on a l'impression qu'il ne s'est rien passé.

```bash
sudo apt install nftables -y
```

Pour vérifier qu'il s'est réellement installé :

```bash
sudo nft --version
```

Et il nous renverra quelque chose comme : `nftables v1.1.3 (Commodore Bullmoose #4)`.

On efface le contenu qu'il pouvait avoir sans supprimer le fichier lui-même. Très important : ne pas le supprimer entièrement juste pour qu'il soit vide, par flemme d'effacer à la main avec nano ce qu'il contient :

```bash
sudo truncate -s 0 /etc/nftables.conf
```

```bash
sudo nano /etc/nftables.conf
```

> [!IMPORTANT]
> Et ici nous utiliserons le contenu du fichier **[CORTAFUEGOS/nftables-PART-1.txt](CORTAFUEGOS/nftables-PART-1.txt)** du dépôt. Attention au nom : il y a aussi un tiret avant le numéro.
> On y établira à la fois le nouveau port que nous avons choisi et le 22 ssh, pour ne pas fermer la session ssh actuellement ouverte.

Pour vérifier la syntaxe du fichier :

```bash
sudo nft -c -f /etc/nftables.conf
```

On applique :

```bash
sudo nft -f /etc/nftables.conf
```

Maintenant, on modifie le fichier ssh pour ajouter le nouveau port (puisque nous avons créé la règle de pare-feu qui n'accepte que depuis l'IP X vers le port Y, qui est le nouveau port SSH) :

```bash
sudo nano /etc/ssh/sshd_config.d/99-hardening.conf
```
Cela donnera ceci :

```conf
Port 22
Port 56769
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowUsers user
MaxAuthTries 3
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
```

Le `Port 22` doit être écrit, il ne suffit pas de l'omettre : dès que tu déclares explicitement un `Port` quelconque, SSH cesse d'écouter sur le 22 par défaut et n'écoute que sur ceux que tu lui indiques. Si tu mettais seulement `Port 56769`, tu perdrais le 22 dès le rechargement.

On vérifie la syntaxe :

```bash
sudo sshd -t
```

```bash
sudo systemctl reload ssh
```

Le `-t` minuscule dit seulement si le fichier est bien écrit. Pour voir **quelle configuration reste réellement**, une fois combinés le `sshd_config` principal, ce qu'apportait le fournisseur et notre fichier, il y a le `-T` majuscule, qui affiche la configuration effective finale :

```bash
sudo sshd -T | grep -Ei '^(port|permitrootlogin|pubkeyauthentication|passwordauthentication|allowusers|maxauthtries)'
```

Si une directive n'affiche pas la valeur que tu viens d'écrire, c'est qu'un autre fichier l'écrase.

On ouvre un autre terminal, **sans fermer le précédent (CTRL + SHIFT + T)**, qui est la bouée de sauvetage : une session déjà ouverte ne tombe pas même si tu changes la configuration, car les changements ne touchent que les nouvelles connexions ; c'est donc avec elle que tu reviendrais en arrière si quelque chose tournait mal. Avec celle-ci ouverte, on essaie de se connecter avec le VPN activé, quel que soit le serveur (donc avec ce nouveau port que nous avons mis) :

> [!IMPORTANT]
> Indispensable de ne pas oublier que, d'après les règles de pare-feu, ON N'ACCÈDE QUE DEPUIS LES IP des proxys de Mullvad ; autrement dit, peu importe que tu aies le VPN activé : si tu essaies de te connecter en ssh au VPS, il ne te laissera pas entrer, car tu NE seras PAS en train d'utiliser l'IP du proxy ; pour utiliser l'IP du proxy, il faut exécuter des commandes, etc... 
> 
> Et c'est pour cela que nous avons fait, au début, la création d'un alias ou raccourci. Et peu importe à quel serveur VPN tu te connectes : il utilisera toujours les mêmes proxys que tu lui as mis en exécutant cet alias.

```bash
ssh dirtyland
```

Cela fonctionnera.

> [!TIP]
> Il est donc recommandé d'essayer avec les trois alias, un par proxy, puis d'essayer d'entrer sans passer par aucun. Ce dernier essai NE devrait PAS nous laisser entrer.

```bash
ssh dirtyland-<pais-1>
```

```bash
ssh dirtyland-<pais-2>
```

En remplaçant `<pais-1>` et `<pais-2>` par les noms que tu as donnés à tes deux alias de secours. Si tu ne t'en souviens pas, le fichier les liste : `grep '^Host dirtyland' ~/.ssh/config`.

> [!TIP]
> **Si, au lieu d'entrer, tu obtiens une erreur, les trois suspects, dans l'ordre :**
>
> - `Could not resolve hostname dirtyland` -> `ssh` ne trouve pas l'alias. Sous Windows, le plus courant est que le fichier ait été enregistré comme `config.txt` ; sur les deux systèmes, qu'il ne soit pas dans le dossier `.ssh` de ton utilisateur.
> - `UNPROTECTED PRIVATE KEY FILE` -> les permissions de la clé privée. Sous Linux, c'est le `chmod 600` ; sous Windows, l'`icacls` de la section 3.2.6.2, qui coupe l'héritage du dossier.
> - `Permission denied (publickey)`, et `ssh -vv dirtyland` affiche `Server accepts key: ...honeypot_vps` juste avant -> **ce n'est ni la clé ni le serveur** : le serveur dit qu'il l'accepte. C'est que `ssh` n'a pas pu signer parce qu'il n'a pas le mot de passe de la clé. Il reste à la charger dans l'agent avec `ssh-add` (ou il s'exécute sans terminal interactif, ou avec `BatchMode=yes`).

Après cela, on modifie de nouveau le fichier ssh, on retire officiellement le port 22 et on ne laisse que le port voulu (56769) :

```bash
sudo nano /etc/ssh/sshd_config.d/99-hardening.conf
```
On retire seulement le port 22.
```conf
Port 56769
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowUsers user
MaxAuthTries 3
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
```

Et voilà. <br>
On se demandera probablement : <br><i>Et la règle de pare-feu du port 22 ?<br>
Faut-il la retirer ?</i><br>
Non, on la garde : Cowrie l'utilisera, puis redirigera de 22 --> 2222.

Très important : on fait un reload, car même si nous avons configuré le port et qu'en effet il ne nous laisse pas entrer, en interne ce port reste occupé. Et plus tard, il ne nous permettra pas de monter Cowrie sur le 22. 

Cette commande NE COUPE PAS NOTRE CONNEXION. Comme le ferait un `restart`.

```bash
sudo systemctl reload ssh
```

On lance un :

```bash
sudo ss -tlnp | grep -E ':(22|56769) '
```

Pour s'assurer que le port 22 a vraiment été libéré. Cela doit apparaître ainsi :

<pre>
LISTEN 0      128          0.0.0.0:56769      0.0.0.0:*    users:(("sshd",pid=639,fd=6))            
LISTEN 0      128             [::]:56769         [::]:*    users:(("sshd",pid=639,fd=7))
</pre>

```bash
sudo systemctl enable nftables
```

```bash
sudo systemctl start nftables
```

De plus, très important, nous allons essayer de nous connecter par le port 22 pour voir si nous ne pouvons vraiment PLUS entrer en ssh par ce port. Depuis l'extérieur, depuis notre propre machine, nous essaierons :

```bash
ssh -i ~/.ssh/honeypot_vps -p 22 user@[IP VPS]
```

`ssh: connect to host [IP VPS] port 22: Connection refused`
- `refused` signifie joignable mais sans service. `timed out` signifie filtré.
- **Port 22, refused :** Le pare-feu a tcp dport 22 accept, donc le paquet SYN traverse nftables et arrive au noyau. Mais dans ss -tulnp, rien n'écoute sur le 22 : seulement le 56769. Faute de processus associé, le noyau répond par un RST, et ton nc le traduit en connexion refusée. Autrement dit, tu es arrivé au bout du chemin et on t'a répondu qu'il n'y a personne.
- **Port 23 ou un port inventé, timed out :** Aucune règle ne les accepte, donc ils tombent dans le policy drop. Le paquet est jeté sans générer la moindre réponse, et ton client attend jusqu'à épuiser les trois secondes du -w 3.

### 3.2.7 Configuration de la deuxième IP.

Comme nous l'avons établi dans la conception (section 3.2.2), la machine dispose de deux IP publiques : la principale (`[IP VPS]`) pour Cowrie et une deuxième (`[IP VPS 2]`) pour Dionaea. Le fournisseur attribue cette deuxième IP sur une interface à part (`ethX`), gérée par cloud-init. Après un redémarrage de la machine, l'interface apparaît configurée automatiquement.

<b>(Facultatif)</b>

```bash
sudo reboot
```

Au retour, on vérifie que l'IP est présente :

```bash
echo " " && hostname -I && echo " " && ip -br a
```

Le seul ajustement nécessaire est de supprimer le conflit de double route par défaut qu'introduit la nouvelle interface. On modifie le netplan et on retire le bloc `routes` de `ethX` (en ne laissant que son IP, sans route par défaut propre). L'interface peut parfois être `eth2`, `eth1` ou une autre. Dans mon cas, il y a trois interfaces.

Une copie de sauvegarde, au cas où.

```bash
sudo cp /etc/netplan/50-cloud-init.yaml /etc/netplan/50-cloud-init__$(date +%Y-%m-%d_%H:%M:%S).yaml.bak
```

Nous n'allons ni effacer son contenu ni rien d'autre, car il a déjà les IP et les MAC associées, tout est correct et nous cherchons seulement à supprimer une chose :

```bash
sudo nano /etc/netplan/50-cloud-init.yaml
```

Contrairement à d'autres fois, ici on ne peut pas simplement copier-coller : à chaque formatage ou nouvelle machine, les MAC changent. Importer ce qu'utilisait une instance ou une machine précédente (comme ses MAC) n'a donc aucun sens.

**Tu retires le bloc routes de eth1.**

<pre>
      routes:
      - to: "default"
        via: "&lt;IP Gateway&gt;"
</pre>

Il est important de mentionner que, dans MON cas, `eth2` correspond à l'IPv6, et rien de plus : simplement, mon VPS ne met pas IPv4 et IPv6 sur une même interface, il sépare et isole tout.

On vérifie la syntaxe :

```bash
sudo netplan generate
```

On applique avec un filet de sécurité (cela revient en arrière tout seul au bout de 20 secondes, au cas où nous perdrions l'accès) :

```bash
sudo netplan try --timeout 20
```

Si l'accès est maintenu, on confirme avec ENTRÉE et on le rend persistant :

```bash
sudo netplan apply
```

On vérifie qu'il reste **une seule** route par défaut :

```bash
ip route show default
```

Il doit sortir **exactement une ligne**. S'il en sort deux, le bloc `routes` est encore présent quelque part et il faut retourner dans `nano`.

Et que les deux IP publiques sont toujours là :

```bash
ip -4 -br addr show scope global
```

<pre>
eth0             UP             [IP VPS]/24
eth1             UP             [IP VPS 2]/24
</pre>

La commande ne contient pas le nom de l'interface, exprès : ici, la deuxième IP est sur `eth1`, mais sur une autre machine elle peut être sur `eth2`, et avec le nom en dur la commande ne renverrait rien et on croirait que l'IP a disparu alors qu'elle s'appelle seulement autrement. Ainsi, la commande les liste **toutes** avec leur interface, et vérifie les deux IP et pas seulement la deuxième : si celle qui manquait était la première, Cowrie n'aurait plus où écouter.

## 3.3 Docker + pare-feu.

On a suivi le guide officiel de Docker pour Debian (https://docs.docker.com/engine/install/debian/), sans écart substantiel par rapport à la procédure recommandée.
Prérequis et suppression des paquets en conflit :

```bash
sudo apt update
```
```bash
sudo apt install -y ca-certificates curl
```
```bash
for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do sudo apt remove -y $pkg; done
```
Sur le serveur, aucun paquet en conflit n'était installé auparavant, donc cette étape n'a rien supprimé.

Ajout de la clé GPG officielle de Docker au trousseau d'APT, nécessaire pour qu'APT puisse vérifier l'authenticité des paquets :
```bash
sudo install -m 0755 -d /etc/apt/keyrings
```

```bash
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
```

```bash
sudo chmod a+r /etc/apt/keyrings/docker.asc
```

Déclaration du dépôt officiel de Docker : première tentative ratée et correction appliquée.
Le guide officiel résout le nom de code de la distribution et l'architecture par substitution de commandes à l'intérieur d'un heredoc :
```bash
printf 'Types: deb\nURIs: https://download.docker.com/linux/debian\nSuites: trixie\nComponents: stable\nArchitectures: amd64\nSigned-By: /etc/apt/keyrings/docker.asc\n' | sudo tee /etc/apt/sources.list.d/docker.sources > /dev/null
```
  
Installation du moteur et de ses composants :

```bash
sudo apt update
```

```bash
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Vérification de l'installation :

```bash
sudo docker version
```

```bash
sudo systemctl status docker --no-pager
```

La version installée était Docker Engine 29.6.1, avec le backend iptables sur la couche de compatibilité iptables-nft (Experimental: false), qui est le backend stable recommandé par Docker à la date de ce déploiement ; le backend nftables natif reste expérimental dans cette version. Le service était actif (systemctl status docker a affiché "active (running)").

L'utilisateur administrateur n'a pas été ajouté au groupe docker. Appartenir à ce groupe revient en pratique à avoir un accès root sans mot de passe, car Docker ne dispose d'aucun mécanisme de vérification équivalent à celui de sudo. Sur un hôte destiné à être exposé à de vrais attaquants, cette voie d'escalade triviale n'est pas acceptable. Toutes les commandes Docker s'exécutent avec sudo.

### <u>3.3.1 Théorie du DNAT et comprendre les règles de pare-feu (Facultatif).</u>

Cette section est de la théorie et il n'y a rien à exécuter.<br>
Elle explique pourquoi toutes les règles qui contrôlent les leurres vont dans la chaîne `forward` et non dans `input`. <br>
Si c'est déjà clair pour toi, saute-la.

**Le problème.** Cowrie et Dionaea sont des conteneurs, et un conteneur n'a pas d'adresse publique. Docker leur attribue des adresses privées de son réseau interne, dans notre cas `172.20.0.10` pour Cowrie et `172.20.0.20` pour Dionaea, avec l'hôte en `172.20.0.1` via le pont `dirtyland0` (nous utilisons un pont à nous au lieu du `docker0` par défaut, c'est tout). Ces adresses n'existent qu'à l'intérieur du serveur. Les seules interfaces exposées à Internet sont `eth0` et `eth1` (_voire `eth2`, selon ton cas_) de l'hôte. La question est donc de savoir comment un attaquant atteint les conteneurs, et la réponse est le DNAT.

**Mais avant cela, qu'est-ce que le NAT ?** <br>
Le NAT (*Network Address Translation*) n'est pas un protocole, c'est une technique. Un protocole définit comment deux parties dialoguent : le format des messages, l'ordre, la signification de chaque champ, comme le font IP, TCP ou HTTP. <br>
Le NAT ne définit aucun nouveau message. Ce qu'il fait, c'est réécrire les adresses dans l'en-tête des paquets d'autres protocoles lorsqu'ils passent par un équipement intermédiaire. Il agit sur les adresses IP, qui sont de couche 3, mais quand il réécrit aussi les ports (la variante PAT ou NAPT, qui est justement ce qui se passe quand on associe un port de l'hôte à un conteneur), il touche aussi la couche 4. Pour être rigoureux, il agit sur la couche 3 et, souvent, sur les ports de la couche 4.

Dans le NAT, il y a deux variantes, selon l'adresse réécrite :

| | Ce qu'il réécrit | Cas habituel |
|---|---|---|
| **SNAT** (*Source NAT*) | L'adresse **source** | Sortir sur Internet : ton IP privée est traduite en une IP publique pour que la destination sache où répondre. C'est ce que fait la box de la maison. |
| **DNAT** (*Destination NAT*) | L'adresse de **destination** | Un paquet qui arrive sur une IP publique est redirigé vers une machine interne. C'est "ouvrir un port", et c'est exactement ce que fait Docker quand il publie celui d'un conteneur. |

Ce qui définit chacune, c'est l'extrémité qu'elle réécrit, indépendamment des types d'adresses en jeu.

**Qui décide de la chaîne (input ou forward) ?** <br>
L'existence d'un DNAT ne détermine pas à elle seule si le trafic ira vers `input` ou vers `forward`. Ce qui le détermine, c'est **la nature de la destination une fois réécrite** : si elle correspond à la machine elle-même, il va vers `input` ; si elle correspond à une autre machine ou à un conteneur vers lequel l'hôte doit retransmettre, il va vers `forward`. Comme la destination réécrite est le conteneur, qui du point de vue du réseau est une autre machine, le trafic des leurres va **toujours** vers `forward`.

Que le paquet passe physiquement par l'hôte n'a pas d'importance, car pour le pare-feu ce qui compte, c'est à qui il est destiné, pas par où il entre. Et c'est le noyau qui en décide, selon une séquence fixe. L'ordre est la clé :

1. Le paquet entre par `eth0` à destination de `[IP VPS 2]:445`, notre IP publique.
2. **Phase PREROUTING.** C'est ici que s'applique le DNAT que Docker a créé en publiant le port. La destination est réécrite et le paquet va maintenant vers `172.20.0.20:445`, le conteneur de Dionaea. La traduction a lieu **avant** que le noyau ne décide du chemin.
3. **Décision de routage.** Le noyau regarde la destination, déjà réécrite, et vérifie si cette IP est à lui ou à une autre machine. Comme `172.20.0.20` n'appartient pas à l'hôte, il conclut que le paquet est à retransmettre.
4. Comme il est à retransmettre, il entre dans la chaîne `forward`. **Il ne touche jamais `input`.**

Comme on le voit, la chaîne `input` protège le trafic destiné à la machine elle-même, comme le SSH d'administration sur le 56769, mais **elle ne voit pas le trafic des conteneurs**. Celui-ci passe par `forward`. C'est pourquoi toutes les règles qui contrôlent les leurres, aussi bien l'entrée vers eux que la sortie vers Internet, s'écrivent dans `forward`, le seul endroit où l'hôte, en jouant le rôle de routeur, décide de ce qu'il retransmet et de ce qu'il ne retransmet pas.

**Où regarder, alors.**

| Pour savoir... | Regarde | Elle est à toi |
|---|---|---|
| Si l'hôte est protégé | `table inet filter`, chaîne `input` | Oui. C'est là qu'est ton SSH du 56769 restreint aux proxys. |
| Si les leurres sont protégés ou exposés | `table inet filter`, chaîne `forward` | Oui. C'est ton vrai point de contrôle sur Docker. |
| Ce que Docker fait en dessous | `table ip nat` et `table ip filter` | Non. Le noyau lui-même prévient avec le `do not touch`. On les lit, on ne les modifie pas. |

Et la distinction entre les deux tables de Docker : **`ip nat` traduit les adresses, `ip filter` décide si le paquet passe**.

Dans `table ip nat` vit le DNAT dont nous avons parlé. Sa chaîne `PREROUTING` est exactement la phase où l'on réécrit la destination de ce qui entre. Avec la pile démarrée et le 445 publié, on y voit la règle qui traduit ton IP publique vers le conteneur ; avec la pile arrêtée, la chaîne `DOCKER` est vide car rien n'est publié. Cette table ne bloque ni n'autorise rien, elle ne fait que traduire. Son `POSTROUTING` fait le travail inverse, le SNAT : la règle de *masquerade* est celle qui permet que, quand un conteneur parle vers l'extérieur, son `172.x` soit réécrit en IP publique pour que la réponse sache revenir.

C'est dans `table ip filter` que Docker décide si le trafic déjà traduit passe, avec sa propre chaîne `FORWARD` (distincte de la tienne) et ses sous-chaînes `DOCKER-USER`, `DOCKER-FORWARD` et autres. Celle-ci, en revanche, autorise ou bloque, mais rappelle-toi ce que l'on vérifie au 3.3.2 : ton `forward` de `inet filter` et la `FORWARD` de Docker sont accrochés au même point du noyau, et comme un `drop` est définitif, **ton `drop` l'emporte sur ce que Docker autorise**. C'est pourquoi la tienne est la gardienne et celle de Docker est secondaire pour toi.

### 3.3.2 Pare-feu POST Docker.

D'abord, une copie de sauvegarde du fichier précédent :

```bash
sudo cp /etc/nftables.conf /etc/nftables__$(date +%Y-%m-%d_%H:%M:%S).conf.bak
```
On le vide de nouveau :
```bash
sudo truncate -s 0 /etc/nftables.conf
```

Et **on met la partie 2 du pare-feu**, qui est le contenu de **[CORTAFUEGOS/nftables-PART-2.txt](CORTAFUEGOS/nftables-PART-2.txt)** du dépôt.

```bash
sudo nano /etc/nftables.conf 
```

Comme nous l'avons fait précédemment, on met simplement la partie 2.

**C'est la même chose que la partie 1, mais avec un seul changement.** <br>
Dans la partie 1, le fichier commençait par `flush ruleset`. Cela ne faisait pas de mal, car Docker n'était pas encore installé et il n'y avait rien d'autre à effacer. Mais maintenant, si. 

Docker a créé ses propres tables (`ip nat`, `ip filter`, `ip6 nat` et `ip6 filter`), qui cohabitent avec la nôtre (`inet filter`) sans se marcher dessus, car leurs familles et leurs noms sont différents. Mais `flush ruleset` **ne vide pas seulement la nôtre : il efface tout**, y compris celles de Docker, et laisse les conteneurs sans traduction d'adresses ni filtrage jusqu'à ce que Docker les recrée.

C'est pourquoi, dans la partie 2, ce `flush ruleset` est remplacé par deux lignes qui réinitialisent uniquement notre table : `add table inet filter` et `delete table inet filter`.

Le `add` crée la table si elle n'existe pas, de sorte que le `delete` qui suit n'échoue jamais en essayant d'effacer quelque chose d'inexistant, et le `delete` la supprime pour la redéfinir proprement juste après. L'effet est une réinitialisation de notre table, et seulement de la nôtre.

Avant de l'appliquer, on vérifie que la syntaxe est correcte :

```bash
sudo nft -c -f /etc/nftables.conf
```

Après avoir écrit le fichier, les commandes qui ont confirmé que la correction fonctionne sont :

```bash
sudo nft -f /etc/nftables.conf
```
```bash
sudo nft list tables
```
Et la sortie qu'elle doit renvoyer :
- table ip nat
- table ip filter
- table ip6 nat
- table ip6 filter
- table inet filter

## 3.4 Cowrie + Dionaea.

> [!IMPORTANT]
> ### Bouton panique.
>
> Pour arrêter le docker compose :
>
> ```bash
> sudo docker compose -f /opt/dirtyland/docker-compose.yml down
> ```
>
> Et pour vider la chaîne `forward`, qui reste en refus parce que `flush` efface les règles mais ne touche pas à la politique :
>
> ```bash
> sudo nft flush chain inet filter forward
> ```
>
> Ces deux commandes vont de la plus radicale à la moins radicale. Après l'une ou l'autre, <b>vérifie-le, ne le suppose pas</b> :
>
> ```bash
> sudo docker ps
> sudo ss -tulnp
> ```
>
> La première doit sortir vide. Dans la seconde, il ne doit rien rester de Cowrie ni de Dionaea : seulement des ports internes de loopback et des services étrangers au projet.

<b>1. Préparation des dossiers</b>

Tout le projet vit sous `/opt/dirtyland`. Au lieu de créer des dossiers au fil du document, nous montons **l'arborescence complète en une seule fois** : ainsi, le point de départ est toujours identique, le montage est reproductible et aucune section ultérieure n'échoue faute d'un répertoire.

```bash
sudo mkdir -p \
  /opt/dirtyland/cowrie/{etc,fs,honeyfs,cmdpatch,keys,parches} \
  /opt/dirtyland/cowrie/txtcmds/usr/bin \
  /opt/dirtyland/dionaea/services-enabled \
  "/opt/dirtyland/Telegram Reports/state" \
  /opt/dirtyland/geoip \
  /opt/dirtyland/monitor \
  /opt/dirtyland/platform-reporter \
  /var/lib/dirtyland-reporter \
  /var/log/dirtyland-reporter
```

L'arborescence se présente ainsi :

<pre>
/opt/dirtyland/
├── docker-compose.yml       # la pila: Cowrie + Dionaea
├── build-dirtyland-fs.sh    # generador del sistema de ficheros falso (3.4.2.3)
├── cowrie/
│   ├── etc/                 # cowrie.cfg, userdb.txt, ps_command_output.json, ayudas-comandos.json
│   ├── fs/                  # fs.pickle: los METADATOS del sistema falso
│   ├── honeyfs/             # el CONTENIDO de los ficheros (aquí se extrae el /home)
│   ├── cmdpatch/            # los .py de los comandos emulados, ya parcheados
│   ├── parches/             # ficheros de la IMAGEN que corregimos (3.4.2.8): protocol.py
│   ├── keys/                # las claves de host SSH, generadas con ssh-keygen (3.4.2.10)
│   └── txtcmds/             # salidas enlatadas que sustituyen a las de Cowrie (3.4.2.8)
├── dionaea/
│   └── services-enabled/    # solo los servicios coherentes con un Windows
├── Telegram Reports/        # alertas de Cowrie: plugin de salida + baneos
│   └── state/               # el ÚNICO directorio con escritura para el contenedor
├── monitor/                 # vigilancia del anfitrión: send-alert.sh, digest, watchers
└── platform-reporter/       # reporte a AbuseIPDB / VirusTotal / MalwareBazaar / ThreatFox / URLhaus
    ├── orchestrator.py      # punto de entrada unico para los dos honeypots
    ├── collectors/          # leen Cowrie y Dionaea -> modelo comun
    ├── reporters/           # uno por plataforma
    ├── common/              # modelo, estado, cuotas, HTTP y la barrera de IPs
    ├── tests/               # comprueban que las puertas saltan (3.5.10)
    └── cron.d/
</pre>

En dehors de `/opt`, on crée deux chemins de service pour les reporters, qui ne sont pas de la configuration mais des données : `/var/lib/dirtyland-reporter` (l'état de ce qui a déjà été signalé, pour ne pas faire de doublons) et `/var/log/dirtyland-reporter` (leurs journaux).

> [!IMPORTANT]
> Trois de ces noms <b>ne peuvent pas être changés</b>, car ils sont écrits dans les scripts du dépôt :
> - `/opt/dirtyland/Telegram Reports/` est utilisé par le plugin `telegram_alert_cowrie.py` et par le service de bannissement, et il est monté dans le conteneur <b>exactement au même chemin</b> que sur l'hôte, pour que la constante du plugin soit valable dedans comme dehors.
> - `/opt/dirtyland/monitor/` est l'endroit où `daily-digest.sh`, `ssh-watch.sh` et `dionaea-watch.sh` cherchent `send-alert.sh` et `telegram.env`, par chemin absolu.
> - `/opt/dirtyland/platform-reporter/config.ini` est la valeur par défaut du reporter, et `malware-watch.sh` et le fichier cron tiennent ce chemin pour acquis.

À partir d'ici, plusieurs sections ont besoin de fichiers du dépôt : le `.tar` du honeyfs, les 70 modules de commandes et leurs sorties préenregistrées, la sortie de `ps`, le `smb.yaml` de Dionaea, le générateur de volumes et le reporter. On les téléverse <b>tous en une fois</b>, maintenant, et le reste du guide va les chercher là.

Sur notre ordinateur, en clonant le dépôt :

```bash
git clone https://github.com/iliangithub/Project_Dirtylands.git
```

Une fois le dépôt téléchargé, <b>le dossier ne se téléverse pas tel quel sur le VPS</b>, il est d'abord empaqueté avec `git archive`, qui extrait exactement ce qui est validé dans le commit et rien d'autre. Cette commande empaquette, transfère, décompresse sur le VPS et efface le `.tar.gz` des deux côtés.

**Sous Linux :**

```bash
cd Project_Dirtylands && git archive --format=tar --prefix=dirtyland-repo/ HEAD | gzip > /tmp/dirtyland-repo.tar.gz && scp /tmp/dirtyland-repo.tar.gz dirtyland:/tmp/ && rm /tmp/dirtyland-repo.tar.gz && ssh dirtyland 'rm -rf /tmp/dirtyland-repo && tar -xzf /tmp/dirtyland-repo.tar.gz -C /tmp/ && rm /tmp/dirtyland-repo.tar.gz && echo subido'
```

**Sous Windows**, cette commande ne convient pas : PowerShell ne comprend pas `&&`, il n'y a pas de `/tmp` et il n'inclut pas `gzip`. C'est la même que ci-dessus avec ce qu'il comprend (`;` pour enchaîner et `if` pour ne pas continuer si quelque chose échoue), et elle se colle aussi en une seule fois :

```powershell
$repo = if (Test-Path .\Project_Dirtylands\.git) { ".\Project_Dirtylands" } else { "." }; git -C $repo archive --format=tar.gz --prefix=dirtyland-repo/ -o "$env:TEMP\dirtyland-repo.tar.gz" HEAD; if ($LASTEXITCODE -eq 0) { scp "$env:TEMP\dirtyland-repo.tar.gz" dirtyland:/tmp/ }; if ($LASTEXITCODE -eq 0) { ssh dirtyland "rm -rf /tmp/dirtyland-repo && tar -xzf /tmp/dirtyland-repo.tar.gz -C /tmp/ && rm /tmp/dirtyland-repo.tar.gz && echo subido"; Remove-Item "$env:TEMP\dirtyland-repo.tar.gz" }
```

Peu importe d'où tu la colles, à côté du dossier ou déjà à l'intérieur.

Trois différences avec celle de Linux : 
- `git archive` compresse tout seul avec `--format=tar.gz` et écrit avec `-o`, donc `gzip` n'est pas nécessaire
- le fichier intermédiaire va dans `%TEMP%` au lieu de `/tmp`, qui n'existe pas sous Windows
- et les `&&` qui restent sont ceux qui sont entre guillemets, exécutés par le `bash` du VPS et non par PowerShell.

> [!CAUTION]
> <b>Pourquoi pas un `scp -r` du dossier.</b> Il copie tout le répertoire de travail et ne lit pas le `.gitignore`, donc il emporte le `.git/` et tous les `__pycache__`. Et le plus grave : notre `.gitignore` exclut exprès `config.ini`, `telegram.env` et `*.sqlite3`, qui sont <b>les clés des cinq plateformes</b> et l'état du reporter. Si tu as déjà exécuté le reporter sur ton ordinateur, ces fichiers existent dans le dossier local et un `scp -r` te les téléverse. Mesuré ici : 1,6 Mo avec `git archive` contre 11,4 Mo avec `scp -r`.

Les transferts passent par l'<b>alias</b> de `~/.ssh/config`, qui contient déjà le port, l'utilisateur, la clé et le `ProxyCommand`. Sans lui, le pare-feu refuse la connexion, car il n'accepte que les IP du proxy de Mullvad.

On vérifie que tout est arrivé :

```bash
cd /tmp/dirtyland-repo && for x in "3.6 Para facilitarnos la vida" "ANALISIS" "CORTAFUEGOS" "COWRIE FAKE ENVIRONMENT" "COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE" "DIONAEA" "DOCKER-COMPOSE" "Local SSH" "README.md" "REPORTING PLATFORM SCRIPTS" "TELEGRAM SCRIPTS"; do [ -e "$x" ] && echo "  OK     $x" || echo "  FALTA  $x"; done; echo "  ----------"; echo "  $(ls -1 | wc -l) de 11 elementos en la raiz"
```

<pre>
  OK     3.6 Para facilitarnos la vida
  OK     ANALISIS
  OK     CORTAFUEGOS
  OK     COWRIE FAKE ENVIRONMENT
  OK     COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE
  OK     DIONAEA
  OK     DOCKER-COMPOSE
  OK     Local SSH
  OK     README.md
  OK     REPORTING PLATFORM SCRIPTS
  OK     TELEGRAM SCRIPTS
  ----------
  11 de 11 elementos en la raiz
</pre>

S'il sort un `FALTA`, le transfert est resté incomplet : on refait l'étape précédente **et on ne continue pas.**

Les scripts du dépôt sont toujours livrés avec des fins de ligne Unix, même s'ils sont téléchargés depuis Windows, et c'est un `.gitattributes` qui le garantit. Si un jour tu copies un script et qu'il échoue avec `203/EXEC` dans systemd ou avec `bad interpreter`, c'est que ce fichier est arrivé avec des fins de ligne Windows : `sed -i 's/\r$//' fichero` le corrige.

```bash
cd /opt/dirtyland
```

```bash
sudo docker pull cowrie/cowrie:3.0.10
```

> [!CAUTION]
> <b>La version de Cowrie est figée, pas en `latest`.</b> Ce montage remplace des fichiers internes de Cowrie, les 70 modules du 3.4.2.8, qui dépendent de son API interne, laquelle change d'une version à l'autre sans prévenir. Cela nous est arrivé avec la `3.0.11`, qui a déplacé `cwd` du protocole vers le shell et transformé `user` d'objet en dictionnaire : l'authentification fonctionnait, le MOTD s'affichait et aucun prompt n'apparaissait. La `3.0.10` est la dernière compatible. Avant de monter de version, il faut vérifier si l'API correspond toujours :
>
> ```bash
> sudo docker run --rm --entrypoint /cowrie/cowrie-env/bin/python3 cowrie/cowrie:<version> -c "
> h=open('/cowrie/cowrie-git/src/cowrie/shell/honeypot.py').read()
> print('COMPATIBLE' if ('self.protocol.cwd' in h and 'self.user[' not in h) else 'API NUEVA: hay que adaptar los modulos')"
> ```

```bash
sudo docker pull cowrie/dionaea@sha256:7c3c1b7e3b0476f9ac17c4568979eb4d6c35c2f56ee1a5b6f3d835267babdc47
```

<b>Dionaea aussi est figée</b>, et par digest plutôt que par étiquette, car le projet ne publie que `latest`. La raison est la même qu'avec Cowrie : nous lui remplaçons le module TDS de l'étape 5, et avec `latest` une nouvelle image pourrait l'apporter modifié et garder notre vieille copie montée par-dessus, sans la moindre erreur. Pour la mettre à jour délibérément, on refait le correctif et on change le digest, que l'on consulte ainsi :

```bash
sudo docker image inspect cowrie/dionaea -f '{{index .RepoDigests 0}}'
```

<b>2. Configuration du daemon Docker</b>

```bash
printf '{\n  "userland-proxy": false,\n  "log-driver": "json-file",\n  "log-opts": { "max-size": "10m", "max-file": "3" }\n}\n' | sudo tee /etc/docker/daemon.json > /dev/null
```
```bash
sudo systemctl restart docker
```

<b>3. Fichiers de configuration de Cowrie</b>
```bash
sudo nano /opt/dirtyland/cowrie/etc/cowrie.cfg
```
Ce que nous y avons mis :
```ini
[honeypot]
hostname = pc-dev-003-ignis

[shell]
kernel_version = 6.12.74+deb13+1-amd64
kernel_build_string = #1 SMP PREEMPT_DYNAMIC Debian 6.12.74-2 (2026-03-08)
hardware_platform = x86_64
operating_system = GNU/Linux
ssh_version = OpenSSH_10.0p2 Debian-7+deb13u4, OpenSSL 3.5.6 7 Apr 2026
```

Pour cet autre fichier, celui des identifiants :

```bash
sudo nano /opt/dirtyland/cowrie/etc/userdb.txt
```
```
root:x:root
admin:x:admin
alyosha:x:alyosha123
user-ssh:x:987654321
```

Le format est `usuario:x:contraseña`, une ligne par compte et sans en répéter aucun. On n'utilise pas non plus le joker `*` ni la négation `!` : un `userdb` avec `*:*:*` accepte n'importe quelle tentative et c'est l'un des signes les plus immédiats qu'il y a un honeypot derrière.

Les mots de passe sont faciles exprès, et `root:root` plus que tout autre, car presque toutes les tentatives visent `root` : si ce compte n'en accepte aucun, le balayage rebondit sans rien capturer. Le prix est le portrait d'une machine mal administrée, qui reste crédible. Sur l'hôte, cela n'ajoute aucun risque, car là-bas `root` par SSH est désactivé et on n'entre qu'avec une clé depuis les IP des proxys : ce fichier décrit le leurre émulé. `mihail` et `mykhailo` ont un répertoire dans `/home` et n'apparaissent pas ici, donc ils existent sans que personne ne puisse s'authentifier avec.

> Par expérience, il est presque obligatoire de mettre "admin" "admin", car les bots ne se donnent même pas la peine de faire une attaque par dictionnaire où la force brute devrait durer plus de 3 ou 4 secondes. Ils vont au mot de passe réellement le plus facile. Peu importe qu'on prenne le mot de passe numéro 1184 du dictionnaire "rockyou.txt" : les bots ne se fatigueront tout simplement pas à faire de la force brute.

Le fichier est monté en lecture seule (`:ro`) dans le conteneur, donc toute modification exige un `sudo docker restart dirtyland_cowrie` pour que Cowrie le relise.

<b>4. docker-compose.yml final</b>

```bash
sudo nano /opt/dirtyland/docker-compose.yml
```

Le contenu de ce docker-compose est dans **[DOCKER-COMPOSE/PART 1/docker-compose.yml](DOCKER-COMPOSE/PART%201/docker-compose.yml)**.

N'oublie pas de remplacer, dans les `ports` de chaque leurre :

- `[IP VPS]` -> la première IP du serveur, celle de Cowrie (ports 22 et 23).
- `[IP VPS 2]` -> la deuxième, celle de Dionaea (445, 135 et 1433).

Et **dès qu'il est collé**, on vérifie que le YAML est correct :

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml config >/dev/null && echo "compose OK"
```

Cela doit répondre `compose OK`. Sinon, ne continue pas : les étapes suivantes montent des volumes et démarrent des conteneurs à partir de ce fichier.

Coller du YAML dans `nano` est délicat, et c'est pourquoi la vérification est ici et pas trois étapes plus loin : si une seule ligne se perd ou fusionne, `docker compose` échoue avec une erreur qui ne dit pas quelle ligne est fautive, du genre `did not find expected key`.

> [!NOTE]
> <b>Seulement si le `config` ci-dessus a échoué.</b> Ne cherche pas la ligne à l'œil. Colle de nouveau le fichier entier. Et si `nano` te décale l'indentation au collage, ouvre-le avec l'indentation automatique désactivée :
>
> ```bash
> sudo nano -I /opt/dirtyland/docker-compose.yml
> ```
>

Chaque leurre est publié lié à <b>son</b> IP, et non sur toutes les interfaces (`0.0.0.0`), donc Cowrie ne répond que par la sienne et Dionaea par la sienne dès le premier démarrage. Dionaea est exposé avec trois ports cohérents avec une machine Windows (SMB 445, RPC 135, MSSQL 1433), et sa personnalisation complète se trouve dans la section 3.4.3.

<b>5. Le correctif MSSQL de Dionaea</b>

Il passe **avant** le démarrage de la pile, et l'ordre n'est pas négociable : le `docker-compose` monte ce fichier, et Docker, quand la source d'un montage de fichier n'existe pas, **crée un répertoire de ce nom**. Dionaea démarrerait alors sans pouvoir importer son propre module.

La raison est la suivante. Un `nmap -sV` contre le 1433 d'un Dionaea par défaut renvoie, sans scripts ni rien :

<pre>
1433/tcp open  ms-sql-s  Dionaea honeypot MS-SQL server
</pre>

nmap a cette signature <b>dans sa base de données d'origine</b> : il reconnaît le paquet de pre-login TDS de Dionaea, qui porte la version gravée en dur et annonce un SQL Server 2000 (`8.0.528`). Ce sont deux problèmes sur la même ligne : le leurre dit son nom, et en plus il prétend être une version qui ne colle pas avec la légende.

Il n'y a pas de clé de configuration pour cela, donc on extrait le fichier de l'image (la même technique qu'avec `createfs.py` au 3.4.2.3) et on change le numéro :

```bash
cid=$(sudo docker create cowrie/dionaea@sha256:7c3c1b7e3b0476f9ac17c4568979eb4d6c35c2f56ee1a5b6f3d835267babdc47) && sudo docker cp "$cid:/opt/dionaea/lib/dionaea/python/dionaea/mssql/include/tds.py" /opt/dirtyland/dionaea/tds.py && sudo docker rm -f "$cid"
```

```bash
sudo sed -i 's/LEIntField("Version",268566536)/LEIntField("Version",1276654090)/' /opt/dirtyland/dionaea/tds.py
```

Et **on vérifie que le `sed` a mordu**, car si l'image changeait cette ligne, le `sed` ne ferait rien et ne dirait rien :

```bash
grep -c 'LEIntField("Version",1276654090)' /opt/dirtyland/dionaea/tds.py
```

<pre>
1
</pre>

S'il sort `0`, le fichier de l'image a changé : il faut regarder comment s'appelle maintenant ce champ avant de continuer, pas l'ignorer.

```bash
sudo chown root:root /opt/dirtyland/dionaea/tds.py && sudo chmod 644 /opt/dirtyland/dionaea/tds.py
```

`1276654090` n'est pas un nombre magique : ce sont les quatre octets `0a 32 18 4c` lus en little-endian, c'est-à-dire la version **10.50 build 6220**, qui est SQL Server 2008 R2 SP3, ce qui est cohérent avec un Windows 7. Pour une autre version, les octets sont `mayor, menor, build-en-2-bytes`.

<b>Et il faut extraire un deuxième fichier du même module : sans lui, n'importe qui peut bloquer Dionaea en envoyant un seul paquet.</b>

Cela m'est arrivé deux fois en une semaine et j'ai dû faire ce correctif en urgence. <br> 
Dionaea a cessé d'enregistrer des connexions et est resté ainsi cinq jours, et après redémarrage il s'est de nouveau bloqué quatre-vingt-dix secondes plus tard, parce que le paquet a été renvoyé. <br>
Les deux fois, les dernières lignes de son journal étaient du MSSQL. Il ne plante pas, il reste à <b>tourner en boucle</b>, et c'est pour cela que personne ne le remarque : `docker ps` continue d'afficher `Up`, le processus existe et `nftables` continue de compter les paquets qui entrent. La seule chose visible est un cœur à 100 % et une base de données qui cesse de grossir.

Le défaut est dans `handle_io_in()`, et ce sont trois lignes consécutives :

<pre>
chunk = data[offset:offset+p.Length]
p = TDS_Header(chunk)      <b>&lt;-- se reescribe p con un trozo truncado</b>
offset += p.Length         <b>&lt;-- y se avanza con el Length del p NUEVO</b>
</pre>

L'en-tête TDS occupe 8 octets et son `Length` est la taille du paquet entier, donc il ne peut pas être inférieur à 8, mais seul le `0` est rejeté. Si quelqu'un déclare <b>1, 2 ou 3</b>, le morceau découpé se retrouve sans les octets où se trouve le `Length`, la nouvelle analyse les remplit de zéros, le `Length` vaut `0`, `offset += 0` et la boucle revient au début avec les mêmes octets. Pour toujours, et sans écrire une ligne, car par ce chemin rien n'est journalisé.

La correction tient en deux lignes et se trouve dans le dépôt, avec son explication complète à l'intérieur :

```bash
cid=$(sudo docker create cowrie/dionaea@sha256:7c3c1b7e3b0476f9ac17c4568979eb4d6c35c2f56ee1a5b6f3d835267babdc47) && sudo docker cp "$cid:/opt/dionaea/lib/dionaea/python/dionaea/mssql/mssql.py" /opt/dirtyland/dionaea/mssql.py && sudo docker rm -f "$cid"
```

```bash
sudo install -m 755 "/tmp/dirtyland-repo/DIONAEA/parche-mssql.py" /opt/dirtyland/dionaea/parche-mssql.py && sudo /opt/dirtyland/dionaea/parche-mssql.py /opt/dirtyland/dionaea/mssql.py
```

<pre>
parcheado: /opt/dirtyland/dionaea/mssql.py
</pre>

```bash
sudo chown root:root /opt/dirtyland/dionaea/mssql.py && sudo chmod 644 /opt/dirtyland/dionaea/mssql.py
```

> [!TIP]
> <b>Si tu METS À JOUR une installation qui fonctionne déjà</b>, ne touche pas au `docker-compose.yml` à la main : il faut ajouter une ligne dans un fichier qui contient déjà tes IP remplacées. Depuis zéro, ce n'est pas nécessaire, car le compose se colle en entier depuis `DOCKER-COMPOSE/PART 1`. Ceci dit ce qui manque sans rien toucher :
>
> ```bash
> sudo /opt/dirtyland/montajes-dionaea.sh
> ```
>
> Et ceci l'ajoute, avec la bonne indentation, en laissant une copie de sauvegarde et en validant le YAML :
>
> ```bash
> sudo /opt/dirtyland/montajes-dionaea.sh --apply
> ```
>
> On peut le lancer deux fois, et la liste vient du compose du dépôt, donc un nouveau montage est pris en compte automatiquement. Si tu ne l'as pas encore installé (il est copié au 3.4.2.9), il fonctionne aussi depuis `/tmp/dirtyland-repo/DOCKER-COMPOSE/montajes-dionaea.sh`. Il existe à cause d'une vraie panne : cette ligne a été collée à la main et s'est retrouvée avec le tiret en double, et sans ce montage Dionaea se bloque de nouveau au premier paquet MSSQL malformé alors que le compose reste du YAML valide.
>

> [!IMPORTANT]
> <b>Le correctif ne devine pas.</b> Si le fichier de l'image n'est pas exactement celui qu'il attend, par exemple après un changement du digest du `docker-compose`, il ne touche à rien, dit `ESTE mssql.py NO ES EL ESPERADO` et sort en erreur. Un correctif appliqué à moitié se monte par-dessus sans signaler le moindre problème, et c'est pire. L'exécuter deux fois ne casse rien : il dit `ya estaba parcheado` et s'en va.
>
> `test_parche_mssql.py` (section 3.7.10) ne vérifie pas que le texte change : <b>il exécute la boucle</b> avec un paquet de `Length = 1`, avant et après, et vérifie que le premier ne se termine jamais et que le second, lui, se termine.

Ce n'est pas nous qui avons introduit le défaut : le `diff` de notre `tds.py` contre celui de l'image tient en une seule ligne, celle du numéro de version. Ce qui a changé, c'est ce qu'on lui a envoyé, car il faut que quelqu'un déclare un `Length` de 1, 2 ou 3, et le fait que le deuxième blocage soit arrivé quatre-vingt-dix secondes après le redémarrage montre que ce trafic est déjà continu. Avec le correctif, `nmap -sV` passe de `Dionaea honeypot MS-SQL server` à `ms-sql-s?` : cela ne transforme pas le port en un SQL Server crédible face à une analyse approfondie, mais il cesse d'annoncer qu'il y a un honeypot derrière.

<b>6. Démarrer la pile</b>

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml up -d
```
### 3.4.1 Règles de pare-feu améliorées pour le docker-compose.

```bash
sudo cp /etc/nftables.conf /etc/nftables_3.4.1.post.docker_creacion_compose___$(date +%Y-%m-%d_%H:%M:%S).conf.bak
```

La règle de pare-feu suivante correspond à celle de la partie 3 ; là encore, elle est dans le dossier du dépôt :

```bash
sudo truncate -s 0 /etc/nftables.conf
```

```bash
sudo nano /etc/nftables.conf
```

Et on y met le contenu de **[CORTAFUEGOS/nftables-PART-3.txt](CORTAFUEGOS/nftables-PART-3.txt)**. Ici, il est important de bien le relire.

```bash
cat /etc/nftables.conf
```

À propos des règles :
- Dans la chaîne input (pas la forward), il y a la règle tcp dport 22 accept, qui ouvre le 22 à n'importe quelle IP. Cette règle était prévue pour le leurre Cowrie. Mais rappelle-toi que le trafic vers le conteneur de Cowrie passe par forward (à cause du DNAT), pas par input, donc cette règle d'input ne rend pas le conteneur joignable. Le résultat net reste un timeout sur le 22, car le forward le bloque. En voyant cette ligne tcp dport 22 accept dans l'input, tu pourrais penser que le 22 devrait se connecter, et non, il ne se connecte pas, car ce qui décide pour le conteneur, c'est le forward, qui le jette.

Pour vérifier la syntaxe du fichier :

```bash
sudo nft -c -f /etc/nftables.conf
```

On applique :

```bash
sudo nft -f /etc/nftables.conf
```

De plus, nous allons vérifier que les conteneurs sont toujours actifs :

```bash
sudo docker ps
```

Quelque chose comme ceci devrait apparaître :

<pre>
CONTAINER ID   IMAGE                   COMMAND                  CREATED        STATUS        PORTS                                                                                                                                NAMES
7d5ee4b4cb4c   cowrie/cowrie:3.0.10    "/cowrie/cowrie-env/…"   20 hours ago   Up 20 hours   [IP VPS]:22->2222/tcp, [IP VPS]:23->2223/tcp                   dirtyland_cowrie
e7f37419a6af   cowrie/dionaea@sha256:7c3c1b…   "/opt/dionaea/entryp…"   26 hours ago   Up 26 hours   [IP VPS 2]:135->135/tcp, [IP VPS 2]:445->445/tcp, [IP VPS 2]:1433->1433/tcp           dirtyland_dionaea
</pre>

Et oui, tout est scellé et toujours pas exposé à Internet. Pour vérifier que c'est vrai :

```bash
IP1=[IP VPS]; IP2=[IP VPS 2]; for par in "$IP1 22" "$IP1 23" "$IP2 135" "$IP2 445" "$IP2 1433"; do nc -vz -w 3 $par; done
```

Windows n'inclut pas `nc`, donc depuis PowerShell c'est cette autre commande (le `3000` correspond aux mêmes trois secondes d'attente du `-w 3`) :

```powershell
$ip1 = '[IP VPS]'; $ip2 = '[IP VPS 2]'; foreach ($prueba in @(@($ip1,22),@($ip1,23),@($ip2,135),@($ip2,445),@($ip2,1433))) { $h,$puerto = $prueba; $t = New-Object Net.Sockets.TcpClient; $abierto = $t.ConnectAsync($h,$puerto).Wait(3000); "{0,-16} {1,-6} {2}" -f $h, $puerto, $(if ($abierto) { 'ABIERTO' } else { 'cerrado o filtrado' }); $t.Close() }
```
<b>Cela doit nous donner une erreur !</b><br> 
`nc: connect to [IP VPS] port 22 (tcp) timed out: Operation now in progress`<br>
Dans PowerShell, la même chose dite autrement : `cerrado o filtrado` sur les cinq.

> [!IMPORTANT]
> <b>Rien n'est encore exposé</b>

#### 3.4.1.1 Pourquoi ces règles : le confinement en sortie expliqué.

Ce qui suit explique les règles que tu viens d'appliquer, une par une.

Un honeypot est, par définition, une machine délibérément laissée à la portée des attaquants. Si fidèlement que Cowrie et Dionaea émulent leurs services, il faut supposer le pire : "que quelqu'un s'échappe de l'émulation et obtienne une exécution de code réelle à l'intérieur d'un conteneur". En sécurité, on conçoit pour le moment où les choses tournent mal, pas en comptant sur le fait qu'elles ne tourneront pas mal.

Le danger de ce scénario n'est pas de perdre la machine, c'est que **la machine devienne une plateforme d'attaque contre des tiers** : scans massifs, déni de service, spam ou propagation, le tout sortant de l'IP publique du projet et donc avec les conséquences juridiques et de réputation pour celui à qui appartient le VPS.

C'est pourquoi le contrôle de la sortie (*egress*) est la pièce centrale du confinement, avec un principe derrière : la barrière <b>n'est pas implémentée dans le honeypot</b>, qui est un logiciel émulé et qui, s'il est compromis, échappe à tout contrôle, mais en dessous, dans la chaîne `forward` du pare-feu de l'hôte, qui continue de commander même si le conteneur tombe. Celle qui confine vraiment, c'est la barrière dure.

<b>La philosophie est permissive mais contrôlée.</b> Bloquer toute la sortie garantit zéro dommage pour les tiers, mais empêche Cowrie de terminer le téléchargement des payloads que l'attaquant ordonne, et avec lui on perd les échantillons. On a choisi d'autoriser le téléchargement en le restreignant au minimum avec des règles chirurgicales, car récolter du malware est l'un des objectifs du projet : n'autoriser que ce dont un téléchargement a besoin et rendre la machine inutile pour tout abus massif.

<b>L'ancrage commun.</b> Toutes les règles d'egress partagent la même condition d'origine : elles ne s'appliquent qu'au trafic qui entre dans le routage depuis le pont des conteneurs (`iifname "dirtyland0"`) et dont l'origine est leur sous-réseau (`ip saddr 172.20.0.0/24`). Nous ne filtrons pas toute la sortie de la machine, seulement celle des conteneurs, le trafic de l'hôte lui-même sort par sa chaîne `output`, en acceptation par défaut.

**Règle 1. Trafic de retour.** On accepte les connexions déjà établies ou liées (`established, related`) et on jette les invalides. C'est la base pour que les réponses au trafic légitime circulent. Quand un téléchargement autorisé ouvre une connexion, le flux de retour appartient à cette connexion et doit pouvoir passer. L'élimination des invalides écarte le trafic à l'état anormal ou corrompu.

**Règle 2. Anti-pivot.** Six règles qui empêchent un conteneur compromis d'atteindre des destinations qu'il ne doit pas toucher :

| Plage | Ce que c'est | Pourquoi on la bloque |
|---|---|---|
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | Adresses privées de la RFC 1918, non routables sur Internet | Empêche un attaquant de sauter vers des réseaux internes : celui du fournisseur, celui d'autres clients ou celui de la machine elle-même |
| `169.254.0.0/16` | *Link-local* ou APIPA, celle qu'un équipement s'attribue quand il ne trouve pas de DHCP | Un conteneur n'a aucune raison légitime d'aller là |
| `100.64.0.0/10` | CGNAT, le bloc réservé à l'usage interne des opérateurs | Ferme une autre voie vers l'infrastructure de l'hébergeur |
| L'IP publique du serveur lui-même | La nôtre | Empêche le conteneur de se retourner contre l'hôte en attaquant ses services, par exemple le SSH d'administration |

Le but commun est de fermer le mouvement latéral. Chaque blocage est journalisé avec le préfixe `DL-EGRESS-PRIV` ou `DL-EGRESS-HOST`.

**Règle 3. Anti-spam.** On bloque la sortie vers les ports de messagerie : le `25` (SMTP), le `465` (SMTP sur TLS) et le `587` (envoi authentifié). La machine ne peut pas servir à envoyer du spam, l'un des abus les plus courants d'un serveur compromis.

**Règle 4. Anti-amplification.** On bloque **tout** l'UDP sortant des conteneurs. Une attaque par amplification consiste à envoyer de petites requêtes UDP avec une origine falsifiée à des serveurs réflecteurs (DNS, NTP, memcached, SSDP), qui répondent avec un volume bien plus grand dirigé vers la victime usurpée. Sans possibilité d'émettre de l'UDP vers l'extérieur, la machine ne peut pas être à l'origine de cela.

On a vérifié expressément qu'un blocage total de l'UDP ne casse pas le leurre. **Les requêtes DNS des conteneurs ne sortent pas par cette voie**. Le résolveur interne de Docker (`127.0.0.11`) retransmet au résolveur de l'hôte (`systemd-resolved`, sur `127.0.0.53`), et c'est l'hôte qui sort sur Internet pour résoudre, par sa chaîne `output`, pas le conteneur par la `forward`.

Une conséquence assumée : un payload servi par <b>TFTP</b>, qui passe par UDP, ne pourrait pas être téléchargé. On l'a accepté parce que l'immense majorité est distribuée par HTTP ou HTTPS sur TCP, et en échange le vecteur d'amplification est fermé sans exception.

**Règle 5. Sortie TCP avec limite de débit.** Elle s'appuie sur un paquet précis : celui qui porte le drapeau SYN, qui est celui qui ouvre toute nouvelle connexion TCP. Filtrer les SYN revient à filtrer les tentatives d'ouverture de connexions.

La première ligne autorise l'ouverture de nouvelles connexions en limitant le rythme à **10 par minute, avec une marge de démarrage de 20**. On tolère jusqu'à vingt ouvertures presque d'affilée et, à partir de là, une nouvelle toutes les six secondes environ. La deuxième jette et journalise (`DL-EGRESS-RATE`) tout ce qui dépasse ce rythme.

La logique de fond est une **asymétrie entre l'usage légitime et l'abus**. Le téléchargement d'un payload, ce sont une ou deux connexions, et cela passe largement. Un scan de ports ou un DDoS doit en ouvrir des milliers par seconde et se heurte immédiatement à la limite. La même règle permet l'un et rend l'autre impossible.

La troisième ligne, accepter le reste du TCP, est celle qui fait fonctionner le téléchargement, car la limite ne s'applique qu'aux <b>ouvertures</b> : une fois la connexion admise, ses paquets suivants ne sont plus des SYN et le fichier se télécharge à vitesse normale. On limite le nombre de nouvelles connexions par minute que la machine peut ouvrir, pas le débit d'un téléchargement déjà autorisé. Et on autorise n'importe quel port de destination, pas seulement le 80 ou le 443, car les attaquants hébergent leurs payloads sur des ports non standard et la limite de débit neutralise déjà l'abus.

**Règle 6. Voiture-balai.** Ce qui n'a correspondu à aucune règle précédente est journalisé (`DL-EGRESS-OTHER`) et jeté. Avec la politique par défaut de la chaîne (`policy drop`), elle garantit que rien d'imprévu ne sorte. Ce qui n'est pas explicitement autorisé reste bloqué.

<b>La journalisation comme alarme.</b> Toutes les règles de blocage laissent une trace avec un préfixe identifiant (`DL-EGRESS-PRIV`, `DL-EGRESS-HOST`, `DL-EGRESS-SMTP`, `DL-EGRESS-UDP`, `DL-EGRESS-RATE`, `DL-EGRESS-OTHER`). En temps normal, les conteneurs ne génèrent presque pas de sortie bloquée ; donc, si des tentatives vers des réseaux privés, des ports de messagerie ou à un rythme élevé commencent à apparaître, c'est le signe que quelque chose dans un conteneur essaie d'échapper au confinement. En plus de protéger, le confinement génère du renseignement.

**Quelle menace neutralise chaque pièce.**

| Abus | Pourquoi c'est impossible |
|---|---|
| Servir de C2 joignable | L'entrée n'est retransmise qu'aux ports des leurres, aucun nouveau service n'est exposé |
| Amplifier | Blocage de l'UDP sortant |
| Scanner ou rejoindre un DDoS volumétrique | Limite de débit des nouvelles connexions |
| Envoyer du spam | Blocage du SMTP |
| Pivoter | Blocage vers les réseaux privés et l'infrastructure du fournisseur |

Le résultat est une machine capable de récolter du malware et inutile comme plateforme d'attaque.

**Vérification.** La conception n'a pas été validée sur le seul papier. On l'a vérifiée depuis l'intérieur d'un conteneur (Dionaea) :

1. Qu'un téléchargement TCP autorisé fonctionne. Une requête vers un serveur web externe sur le 80 a renvoyé un `200`. Le même test a confirmé que la résolution de noms fonctionnait sans aucune règle DNS dans la `forward`, comme prévu.
2. Que l'accès à un réseau privé est bloqué. Une tentative vers `10.0.0.1` a été bloquée et journalisée avec `DL-EGRESS-PRIV`, avec l'origine et la destination.
3. Que l'UDP sortant est bloqué. L'envoi d'un paquet UDP vers un serveur externe a été bloqué et journalisé avec `DL-EGRESS-UDP`.

<b>Portée honnête.</b> Aucun confinement n'est absolu : ceci n'élimine pas le risque, il le réduit au minimum que nous jugeons acceptable. Même si quelqu'un s'échappait de l'émulation, il ne pourrait ni envoyer de spam, ni amplifier, ni pivoter, car ces vecteurs sont entièrement fermés ; il pourrait seulement scanner ou tenter un DDoS à un rythme inutile. L'idée de départ est de considérer comme acquis qu'on peut te compromettre et de limiter à l'avance ce que la machine peut faire vers l'extérieur.

### 3.4.2 Personnaliser et améliorer Cowrie.

Dans cette section, nous étendons le `docker-compose` pour monter l'arborescence de répertoires factice, la configuration personnalisée et les alertes. Le compose grandit par phases, car chaque couche est vérifiée avant de passer à la suivante.

#### 3.4.2.1 Construction de l'arborescence factice (honeyfs).

L'arborescence que l'attaquant verra dans Cowrie (le compte d'"Alyosha" et compagnie, avec ses dotfiles, ses clés SSH, ses historiques et le projet Node) a été conçue et construite à part, et nous n'entrerons pas dans le détail de la façon dont cela a été fait. <br>

Afin de doter le leurre d'une histoire crédible et cohérente. La construction du contenu et sa conception narrative ont été faites en externe. Ici, nous documentons comment cela s'intègre dans Cowrie.

<p>
Mais, pour faire court, les fichiers ont simplement été créés avec Claude Code sur une machine Debian 13, tout le `home` est converti en archive empaquetée (et non compressée) et transféré sur la machine hôte. L'archive compressée serait par exemple un `.rar` ; dans notre cas, c'est une archive `.tar` (qui préserve les dates de modification, ce qui est important pour le réalisme).
</p>

Nous recommandons qu'elle soit au format `.tar` et non `.rar`. Nous n'allons pas non plus expliquer l'aventure que ce serait si c'était un `.rar`, ni comment résoudre quoi que ce soit dans ce cas.

On utilise `.tar` parce qu'il préserve les `mtime`. Un `.rar` créé sous Windows ne transporte ni les permissions POSIX ni les propriétaires, donc ces métadonnées devraient être reconstruites à part.

Le `.tar` est dans le dossier **COWRIE FAKE ENVIRONMENT**, donc il est déjà arrivé avec le dépôt à la section 3.4 et il suffit de le mettre à sa place. <b>Attention au nom de destination</b> : il doit s'appeler `/tmp/home.tar`, pas le nom qu'il porte dans le dépôt.

```bash
cp "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/honeyfs-home-DEFINITIVO.tar.gz" /tmp/home.tar
```

Et on vérifie qu'il conserve les "mtime" d'origine. Les dates conçues (de 2026) doivent apparaître, pas la date du jour :

```bash
tar -tvf /tmp/home.tar | head -5
```

> [!IMPORTANT]
> Le nom `/tmp/home.tar` n'est pas une préférence : c'est le chemin que le générateur du système de fichiers (`build-dirtyland-fs.sh`, section 3.4.2.3) porte écrit en dur, dans sa variable `HOME_TAR`, et aussi celui qui est extrait dans le honeyfs à la section 3.4.2.5. S'il est téléversé sous un autre nom, le build ne trouve pas l'arborescence et le leurre est généré sans `/home`. L'extension n'a pas d'importance : `tar` détecte tout seul que le fichier est compressé.

#### 3.4.2.2 Le problème du pickle et pourquoi on le régénère entièrement.

Cowrie ne représente pas son système de fichiers virtuel avec les vrais fichiers, mais avec un index au format "pickle" (`fs.pickle`) qui stocke les métadonnées (nom, type, uid, gid, taille, permissions et date) de chaque chemin. Le contenu réel de chaque fichier est servi à part, depuis un répertoire "honeyfs".

Cela a deux conséquences clés :

- Un fichier a besoin <b>des deux pièces</b> pour que l'attaquant le voie avec du contenu : une entrée dans le pickle (les métadonnées) et un vrai fichier dans le honeyfs (le contenu).
    - Si l'entrée du pickle manque, le fichier est invisible même s'il est dans le honeyfs.
- Le pickle fourni d'origine avec Cowrie est une photo d'une vieille Debian (12.5) et ne contient pas nos utilisateurs.
    - On ne peut pas le "fusionner" avec le nôtre ; il faut le <b>régénérer entièrement</b> depuis un vrai système Debian qui inclut à la fois la base du système et notre arborescence.

Évidemment, ces métadonnées de chaque fichier, on ne les fait pas à la main. L'outil qui génère le pickle est `createfs.py`, qui parcourt un vrai système de fichiers et note ses métadonnées. Il vit dans le conteneur de Cowrie, donc on confirme d'abord le vrai nom du conteneur (Docker Compose le préfixe avec le nom du projet) :

```bash
sudo docker ps --format '{{.Names}}\t{{.Image}}'
```

Et on l'extrait pour l'utiliser dans la génération :

```bash
sudo docker cp dirtyland_cowrie:/cowrie/cowrie-git/src/cowrie/scripts/createfs.py /tmp/createfs.py
```

L'image de Cowrie est minimale et n'inclut ni `ls`, ni `find`, ni `grep`. Pour regarder dedans, il faut utiliser `docker cp` ou le Python de son propre environnement virtuel (`/cowrie/cowrie-env/bin/python3`).

Deux détails du code de `createfs.py`. Le champ de date qu'il stocke dans le pickle est le `mtime` et non le `ctime`, ce qui est ce que nous voulons : les dates conçues dans l'arborescence survivent intactes. Et les <b>liens symboliques ne sont conservés que si leur destination tombe dans l'arborescence traitée</b> ; la nôtre n'en avait aucun, mais il vaut mieux le savoir au cas où on en ajouterait un.

#### 3.4.2.3 Génération du pickle depuis une vraie Debian 13.

<b>Pourquoi depuis une Debian complète et pas à la main ?</b> Parce que `createfs.py` n'invente rien : il a besoin de <b>parcourir un vrai système</b> pour le photographier. Nous fabriquons ce qui doit être faux, l'histoire de notre `/home`, et nous copions ce qui doit être vrai, le système avec ses ~69 000 chemins et ses permissions exactes. Une taille qui ne correspondrait pas au vrai binaire de Debian serait un indice.

La stratégie consiste à démarrer un conteneur Debian 13 éphémère (cohérent avec la version qu'annonce Cowrie), à y installer les logiciels que la légende exige, à injecter notre arborescence `/home` par-dessus, à créer les utilisateurs avec leurs uid fixes, à normaliser les permissions et les propriétaires, et seulement ensuite à exécuter `createfs.py`.

D'abord, on télécharge l'image de base :

```bash
sudo docker pull debian:13
```

Le processus est encapsulé dans un script, arrivé avec le dépôt dans le dossier **COWRIE FAKE ENVIRONMENT**. On le copie et on lui donne la permission d'exécution :

```bash
sudo install -o root -g root -m 750 "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/build-dirtyland-fs.sh" /opt/dirtyland/
```

On l'exécute :

```bash
sudo bash /opt/dirtyland/build-dirtyland-fs.sh
```

<b>Sur le VPS, il tourne sans limite de ressources, et c'est voulu.</b> Le script accepte `LIMITES_CPU`, `LIMITES_CPUSET` et `LIMITES_MEM`, mais ils sont vides par défaut : le VPS n'a qu'un seul processeur, et épingler le conteneur sur d'autres cœurs ne ralentit pas le VPS, cela l'empêche de démarrer (`Requested CPUs are not available`). De plus, c'est ici qu'on <b>installe les paquets de la légende</b>, donc un petit plafond de mémoire n'est pas gratuit non plus. Là où ils servent, c'est pour faire un essai sur un ordinateur de bureau :

```bash
LIMITES_CPU=0.5 LIMITES_CPUSET=12-19 LIMITES_MEM=2g bash build-dirtyland-fs.sh
```

> [!TIP]
> <b>Essayer la régénération en dehors du VPS.</b> Les cinq chemins du script (`IMAGE`, `HOME_TAR`, `CREATEFS`, `OUT_DIR`, `HONEYFS_DIR`) ont par défaut ceux de la production, mais on peut les remplacer par des variables d'environnement et exécuter toute la chaîne sur une autre machine Debian avec Docker avant de toucher au leurre :
>
> ```bash
> SUDO="" OUT_DIR=/tmp/ensayo/fs HONEYFS_DIR=/tmp/ensayo/honeyfs \
>   HOME_TAR=/tmp/home.tar CREATEFS=/tmp/createfs.py \
>   bash build-dirtyland-fs.sh
> ```
>
> `SUDO=""` retire le `sudo` quand l'utilisateur est déjà dans le groupe `docker`. Entre deux essais, il faut effacer le `fs.pickle.new` précédent, car `createfs.py` refuse d'écraser sa propre sortie ; le script le vérifie au début, sinon l'erreur surgit à la fin, après l'installation de tous les paquets.
>
> Il faut deux pièces qui ne sont pas dans le dépôt. Le `home.tar`, lui, est fourni avec ; le `createfs.py` s'extrait de l'image exacte que fixe le `docker-compose`, pas de GitHub, pour que ce soit la même que celle qui tourne sur le VPS :
>
> ```bash
> cid=$(docker create cowrie/cowrie:3.0.10)
> docker cp "$cid:/cowrie/cowrie-git/src/cowrie/scripts/createfs.py" /tmp/createfs.py
> docker rm -f "$cid"
> ```
>

Le conteneur de construction est lancé avec `--network host` parce que son téléchargement de paquets, en sortant par le réseau par défaut de Docker, tomberait dans la `policy drop` du pare-feu. C'est une exception ponctuelle et seulement pendant la construction.

> [!WARNING]
> Le pickle fraîchement généré **n'est pas encore fiable**. Pour une vingtaine de fichiers système (sa liste interne `EMBED_PATHS` : `/etc/hostname`, `/etc/hosts`, `/etc/resolv.conf`, `/proc/version`, `/proc/cpuinfo`, `/proc/meminfo`, `/proc/modules`), `createfs.py` ne note pas de métadonnées, il incruste le contenu. Et comme ce conteneur tourne avec `--network host` sur un VPS virtualisé, ils arrivent avec des **données réelles de l'hôte** : le hostname du serveur, des références à `cloud-init`, un `resolv.conf` qui dit "Generated by Docker Engine", les modules noyau de Docker, le drapeau `hypervisor` dans le CPU et les 2 Go de RAM réels. Il faut **l'assainir** avant de l'installer, et c'est ce que fait la section suivante.

#### 3.4.2.4 Vérification et assainissement du pickle avant de l'installer.

L'arborescence est sortie parfaite, donc l'assainissement n'y touche pas : il réécrit seulement cette vingtaine de fichiers spéciaux. Ceux de `/proc` parce qu'ils sont virtuels et que le noyau les génère à la volée, de sorte que dans le conteneur ils décrivent le vrai matériel du VPS, et ceux du réseau parce qu'avec `--network host` ils ont hérité de l'identité de l'hôte.

Cowrie inclut un outil (`dumpfs.py`) pour vider le pickle en texte et l'auditer. On l'extrait et on vérifie que les utilisateurs, les uid, les permissions et le contenu sont corrects :

```bash
sudo docker cp dirtyland_cowrie:/cowrie/cowrie-git/src/cowrie/scripts/dumpfs.py /tmp/dumpfs.py
```

**On vérifie que les cinq utilisateurs sortent avec leurs bons uid et avec le home en `40750` :**

Le `40750` (`drwxr-x---`) est ce qui empêche un utilisateur de fouiller dans le home d'un autre. Avec `40755`, le leurre laisserait n'importe quel compte lister les projets et les clés des autres, et le contrôle des permissions des modules n'aurait rien à refuser. C'est `build-dirtyland-fs.sh` qui le fixe, car `useradd -m` les crée en `0755`.

```bash
sudo python3 /tmp/dumpfs.py /opt/dirtyland/cowrie/fs/fs.pickle.new | grep -E '^/home/(mihail|admin|user-ssh|mykhailo|alyosha)\s'
```
La sortie attendue :

/home/admin	    DIR	40750	1001:1001	4096<br>
/home/alyosha	DIR	40750	1004:1004	4096<br>
/home/mihail	DIR	40750	1000:1000	4096<br>
/home/mykhailo	DIR	40750	1003:1003	4096<br>
/home/user-ssh	DIR	40750	1002:1002	4096<br>

**On vérifie les permissions critiques (clés SSH en 600, .env en 600) et que la base est Debian 13 :**

```bash
sudo python3 /tmp/dumpfs.py /opt/dirtyland/cowrie/fs/fs.pickle.new | grep -E '/home/alyosha/\.ssh/|/home/admin/ignis api/\.env'
sudo python3 /tmp/dumpfs.py /opt/dirtyland/cowrie/fs/fs.pickle.new | grep -E '^/etc/(debian_version|passwd)\s'
```

/home/admin/ignis api/.env	REG	100600	1001:1001	332<br>
/home/alyosha/.ssh/id_ed25519	REG	100600	1004:1004	419<br>
/home/alyosha/.ssh/id_ed25519.pub	REG	100644	1004:1004	108<br>
/home/alyosha/.ssh/known_hosts	REG	100644	1004:1004	237<br>
/etc/debian_version	REG	100644	0:0	5<br>
/etc/passwd	REG	100644	0:0	1190<br>

**On vérifie que le "tell" de Docker (`/.dockerenv`) a été supprimé (cela doit sortir vide) :**

```bash
sudo python3 /tmp/dumpfs.py /opt/dirtyland/cowrie/fs/fs.pickle.new | grep -iE 'dockerenv'
```

Cela ne renvoie rien.

Il manque le plus important, qui ne se voit pas en regardant l'arborescence : **quel contenu `createfs.py` a incrusté dans les fichiers système**. Il vient du véritable hôte, et c'est pourquoi il porte ses données. Dans notre cas, il trahissait douze choses, toutes parce que le pickle avait été généré sur un VPS virtualisé et avec `--network host` :

| Fichier | Ce qu'il trahissait |
|---|---|
| `/etc/hostname`, `/etc/hosts` | Le hostname **réel** du serveur, et des traces de `cloud-init` |
| `/etc/resolv.conf` | Littéralement `# Generated by Docker Engine`, et le domaine du fournisseur |
| `/proc/modules` | Les modules de Docker (`veth`, `bridge`, `br_netfilter`, `xt_MASQUERADE`) : l'empreinte d'un hôte de conteneurs |
| `/proc/cpuinfo` | Le drapeau `hypervisor`, le mouchard classique de la virtualisation, et un Xeon Gold de serveur avec un seul cœur |
| `/proc/meminfo` | Les 2 Go réels du VPS |
| `/proc/version` | Un noyau avec le suffixe `-cloud` et une autre date de compilation. Il contredit le `uname -a` |
| `/etc/os-release` | Vide, parce que c'est un lien vers `/usr/lib/os-release`, qui n'est pas dans `EMBED_PATHS`. Et c'est l'une des premières choses que tout le monde regarde |
| `/etc/localtime` | `Etc/UTC` au lieu du fuseau de la légende. Sous Debian 13, ce lien **est** le fuseau horaire, car `/etc/timezone` n'existe plus |
| `/etc/group` | Le groupe `sudo` vide, avec un `.bash_history` plein de `sudo apt` |
| `/etc/shadow` | Tous les comptes verrouillés et datés du jour du build, pas de mars comme le dit la légende |
| `/proc/mounts`, `/etc/mtab` | Des liens vers le PID du conteneur de construction, donc **cassés** : `cat /etc/mtab` ne renvoyait rien |
| `/proc/9355`, `/proc/self` | Un répertoire avec le PID du build. Un `ls /proc` montre deux nombres et le second n'apparaît pas dans `ps aux` |

Trois autres se corrigent **en dehors du pickle**, au 3.4.2.8 : `ps` montrait des processus d'une autre machine, `netstat` trahissait une Ubuntu et `free` donnait la RAM de l'hôte.

Les fichiers de `/proc` ne peuvent pas être écrits à la main dans le conteneur, donc la seule voie est de réécrire les octets déjà incrustés dans le pickle. C'est le rôle de `sanitize-pickle.py`, qui les rend cohérents avec la légende : un PC de développement avec un i5-12400, 16 Go de RAM, un noyau sans `-cloud`, le DNS du LAN de l'entreprise et `alyosha` dans le groupe sudo. Il les écrit aussi dans le `honeyfs`, car certaines commandes émulées, comme `free`, les lisent sur le disque et non dans le pickle.

Le script est dans **COWRIE FAKE ENVIRONMENT**, donc il est aussi fourni avec le dépôt :

```bash
cp "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/sanitize-pickle.py" /tmp/sanitize-pickle.py
```

Pour ensuite l'exécuter. Il reçoit le pickle fraîchement généré, écrit le pickle final assaini et, au passage, peuple le `honeyfs` avec les fichiers que le code émulé lit sur le disque :

```bash
sudo python3 /tmp/sanitize-pickle.py /opt/dirtyland/cowrie/fs/fs.pickle.new /opt/dirtyland/cowrie/fs/fs.pickle /opt/dirtyland/cowrie/honeyfs
```

Remarque l'ordre : `fs.pickle.new`, le sale, entre, et `fs.pickle`, le définitif, sort. Ainsi, le `.new` reste comme sauvegarde de l'état non assaini.

La première chose qu'il fait est de rendre **lisibles** `/proc/mounts` et `/etc/mtab`, et d'écrire l'histoire du disque :

<pre>
Corrigiendo /etc/mtab y /proc/mounts:
  OK: /etc/mtab -> /proc/mounts
  OK: /proc/mounts pasa de enlace roto a fichero con la tabla
</pre>

<b>Pourquoi une seule table.</b> `/proc/mounts`, `/etc/mtab` et la commande `mount` disent la même chose sur un vrai Linux, donc les trois sortent de la constante `PROC_MOUNTS` du script. Les maintenir séparément, c'est garantir qu'un jour elles ne correspondront plus. Les tailles ne sont pas libres non plus : `/dev` fait la moitié de la mémoire qu'annonce le `dmesg` préenregistré, `/run` 10 % de `MemTotal` et `/dev/shm` 50 %, qui sont les calculs que font le noyau et systemd, donc `df -h`, `mount` et `/proc/meminfo` concordent d'eux-mêmes. Et le disque est un NVMe parce que `/proc/modules` charge `nvme` et non `ahci`.

`/proc/mounts` reste un fichier au lieu d'un lien vers `/proc/self/mounts`, et c'est un compromis conscient : un `ls -l` montre un fichier là où une Debian montre un lien, mais en échange `cat /proc/mounts` fonctionne.

Et il retire la trace du conteneur qui l'a généré :

<pre>
Quitando el PID del contenedor de construccion:
  OK: /proc/9355 renombrado a /proc/48230 (el bash de ps)
  OK: /proc/self -> /proc/48230
</pre>

Le nombre n'est pas choisi au hasard : **48230 est le `-bash` que déclare `ps_command_output.json`**, donc le PID qui apparaît dans `ls /proc` est l'un de ceux que `ps aux` reconnaît. On ne clone pas les 85 processus du JSON, car chacun entraînerait sa cinquantaine de fichiers de `/proc/<pid>/`.

Avant cela, il corrige **les destinations de tous les liens symboliques**, qui se comptent par milliers :

<pre>
Corrigiendo los enlaces simbolicos:
  OK: 7453 destinos de enlace con su barra inicial
</pre>

<b>Pourquoi il faut y toucher.</b> `createfs.py` enregistre la destination avec `os.path.realpath(path)[len(localroot):]`, et avec `localroot="/"` cela lui retire la barre initiale. Le résultat se voit dans n'importe quel `ls -l` du leurre :

<pre>
localtime -> usr/share/zoneinfo/Europe/Kyiv
S01cron   -> etc/init.d/cron
</pre>

Un vrai Linux affiche `/usr/share/zoneinfo/Europe/Kyiv`, et ce n'est pas un lien isolé : cela touche tous ceux du système de fichiers. Cela faussait en plus la taille, car le `st_size` d'un lien est la longueur de la destination d'origine (`../init.d/cron`, 14) et ce qui est enregistré est la destination résolue (`etc/init.d/cron`, 15), donc on recalcule la taille. Ce qui ne se récupère pas, c'est la forme relative, que `realpath` a déjà perdue : il reste un lien absolu, valide et cohérent, même si une Debian par défaut a là un lien relatif.

Et il prévient s'il manque la liste de paquets qui alimente le `dpkg -l` :

<pre>
Lista de paquetes para dpkg -l:
  OK: 558 paquetes, del mismo contenedor que el pickle
</pre>

Il n'y a pas besoin de le copier où que ce soit : le `docker-compose` le monte depuis `fs/`, qui est l'endroit où le générateur le laisse, à côté du pickle. **C'est voulu.** Le copier à la main serait une étape de plus, et le jour où l'on régénérerait le système de fichiers sans la refaire, le leurre resterait avec le nouveau pickle et l'ancienne liste de paquets : deux versions différentes de lui-même, sans aucune erreur pour le signaler. Les artefacts qui **sont générés** vivent tous dans `fs/` et sont montés depuis là ; dans `etc/`, il n'y a que ce qui vient tel quel du dépôt.

<b>Pourquoi le `dpkg -l` ne contient pas sa liste.</b> Il la contenait, une table de 26 paquets écrite à la main, et elle avait vieilli sans que rien ne prévienne : 20 de ces 26 versions ne correspondaient plus à Debian 13 et l'une contredisait la bannière que le leurre lui-même annonce. De plus, 26, c'est peu, alors qu'une `debian:13` fraîchement téléchargée en contient déjà 78. Maintenant, la liste sort du même conteneur qui génère le pickle, donc le `dpkg -l` et le faux disque ne peuvent pas diverger, et le module ne fait que la formater en reproduisant les colonnes, qui s'ajustent au contenu.

Entre-temps, il corrige le fuseau horaire, qui sous Debian 13 vit dans un lien et non dans un fichier :

<pre>
Corrigiendo la zona horaria:
  OK: /etc/localtime -> usr/share/zoneinfo/Europe/Kyiv
</pre>

S'il sort un `AVISO: ... no esta en el pickle`, l'assainisseur **laisse le lien tel qu'il était** au lieu de le laisser cassé en pointant vers un fuseau qui n'existe pas dans l'arborescence : un lien cassé trahit plus qu'un UTC. Cela voudrait dire que `tzdata` n'est pas entré dans le conteneur de construction.

Le fuseau finit par être indiqué à <b>trois</b> endroits, et les trois doivent coïncider, car ils servent des lecteurs différents : la variable `TZ` du service et le montage de `/etc/localtime` gouvernent les processus du conteneur, d'où viennent les dates qu'affiche le leurre, et ce lien dans le pickle est celui que voit l'attaquant avec un `ls -l /etc/localtime`. Si le leurre répond avec l'heure de Kyiv et que son `/etc/localtime` dit `Etc/UTC`, ce sont deux moitiés du même mensonge qui ne tiennent pas ensemble.

L'assainisseur se termine par deux choses de plus, ajoutées lors de l'activation de telnet :

**Contrôle de cohérence.** Il prévient si le leurre proposait le 23 sans rien sur son disque pour l'expliquer. Ce sont **deux** lignes, et il faut les deux :

<pre>
Coherencia de telnet:
  OK: el pickle trae inetd, su configuracion y el servidor
  OK: /etc/inetd.conf declara telnet sin comentar
</pre>

Si, à la place, il sort un `AVISO: faltan en el pickle: ...`, ce sont les paquets qui manquent : il faut les ajouter à `PACKAGES` et régénérer. Il n'interrompt pas, car un pickle sans telnet reste valable pour SSH, mais il refuse de passer inaperçu, ce qui est exactement ce qu'il faut : la dégradation serait invisible au démarrage.

<b>Pourquoi on regarde à deux endroits.</b> Le listing vient du pickle, mais le contenu de `/etc/inetd.conf` ne figure pas dans `EMBED_PATHS`, donc il arrive vide et ce que répond un `cat` vient du honeyfs. Vérifier seulement la première moitié donnait un <b>OK trompeur</b> : `inetutils-telnetd` sous trixie installe seulement le binaire et n'enregistre rien, donc le fichier arrivait entièrement commenté alors que le leurre répondait sur le 23, et un `cat` montrait une machine qui n'explique pas son propre port ouvert.

L'avertissement, s'il se déclenche, est `AVISO: /etc/inetd.conf NO declara telnet`. C'est Debian lui-même qui active la ligne dans le conteneur de construction avec `update-inetd --enable telnet` : elle est déjà dans le fichier, désactivée avec le marqueur `#<off>#`.

**Installation des `/etc` par défaut.** L'assainisseur copie dans le honeyfs ce que `build-dirtyland-fs.sh` a exporté dans `fs/honeyfs-etc/`, et il le fait dans la même commande pour qu'il n'y ait pas d'étape manuelle qu'on puisse oublier :

<pre>
  OK: /opt/dirtyland/cowrie/honeyfs/etc/inetd.conf      (de Debian, no inventado)
  OK: /opt/dirtyland/cowrie/honeyfs/etc/issue           (de Debian, no inventado)
  OK: /opt/dirtyland/cowrie/honeyfs/etc/issue.net       (de Debian, no inventado)
  OK: /opt/dirtyland/cowrie/honeyfs/etc/ssh/sshd_config (de Debian, no inventado)
</pre>

<b>Deux origines, et la différence compte.</b> Les fichiers de la légende (`hostname`, `hosts`, `resolv.conf` et la destination de `localtime`) sont <b>inventés</b>, car ils doivent mentir. Ceux par défaut (`issue`, `issue.net`, `inetd.conf` et `ssh/sshd_config`) sont <b>copiés</b> d'une vraie Debian, car ils ne dépendent pas de notre histoire et les écrire à la main, ce serait inventer un format ; dans le `sshd_config`, on change `PermitRootLogin yes` avant de le copier, car le leurre accepte `root` avec mot de passe. Et `etc/issue.net` n'est pas décoratif : c'est de là que Cowrie tire la bannière de telnet, et s'il manque, il écrit `ERROR: Failed to load /etc/issue.net` à chaque démarrage et sert une bannière vide.

On vérifie que la bannière est correcte :

```bash
sudo cat /opt/dirtyland/cowrie/honeyfs/etc/issue.net
```

Et que le pickle contient déjà le serveur telnet et sa configuration :

```bash
sudo python3 /tmp/dumpfs.py /opt/dirtyland/cowrie/fs/fs.pickle | grep -E '^/(etc/inetd\.conf|usr/sbin/(inetd|tcpd|in\.telnetd|telnetd))\s'
```

Qu'ils existent ne suffit pas : il faut voir ce que l'attaquant verrait en ouvrant le fichier. La ligne de telnet doit sortir **non commentée**, ainsi que les deux binaires qu'elle cite dans la commande précédente :

```bash
sudo grep -vE '^\s*#|^\s*$' /opt/dirtyland/cowrie/honeyfs/etc/inetd.conf
```

<pre>
telnet	stream	tcp	nowait	root	/usr/sbin/tcpd	/usr/sbin/telnetd
</pre>

Si cette ligne sort précédée de `#<off>#`, le fichier est tel que Debian le laisse d'origine et le `update-inetd --enable telnet` du 3.4.2.3 n'a pas été exécuté.

Ceci assainit le <b>pickle</b>, mais il y a une <b>deuxième partie</b> : trois commandes que Cowrie émule (`ps`, `netstat`, `free`) trahissent aussi l'environnement réel et doivent être montées comme binds dans le compose ; elles sont donc assainies à la section 3.4.2.8, une fois celui-ci défini.

#### 3.4.2.5 Préparer le honeyfs (contenus).

Le honeyfs est le répertoire qui contient le contenu réel des fichiers. On l'extrait du même tar, en respectant le chemin.

<b>Pourquoi la même arborescence deux fois ?</b> Parce que le pickle stocke les <b>métadonnées</b> (ce que voit un `ls -la`) et le honeyfs le <b>contenu</b> (ce que voit un `cat`). Les deux sortent du même tar pour que les tailles et le contenu concordent.

```bash
sudo tar -xpf /tmp/home.tar -C /opt/dirtyland/cowrie/honeyfs
```

On vérifie qu'il est tombé au bon endroit (les cinq utilisateurs sous `honeyfs/home/`) et que les dates restent celles qui ont été conçues et non celles du jour :

```bash
ls -la /opt/dirtyland/cowrie/honeyfs/home/
sudo find /opt/dirtyland/cowrie/honeyfs/home -newermt '30 days ago' | head
```

La première commande doit lister `admin`, `alyosha`, `mihail`, `mykhailo` et `user-ssh` ; la seconde ne doit rien renvoyer (si elle renvoie des fichiers, le `.tar` a été créé ou extrait en perdant les `mtime`, et toute l'arborescence apparaîtrait comme fraîchement créée).

Le `-p` de `tar` préserve les permissions et, en extrayant en root, aussi les propriétaires. C'est important parce que le `.env` et les clés SSH du leurre doivent rester en `600` : un fichier d'identifiants lisible par tous est aussi suspect que de ne pas en avoir.

#### 3.4.2.7 Alertes en temps réel via Telegram (Cowrie).

Ceci ne nécessite pas de toucher au pare-feu : le DNS du conteneur est résolu par Docker en interne, sans sortir par `dirtyland0`, donc le blocage de l'UDP sortant ne l'affecte pas, et le TCP/443 sortant était déjà autorisé.

Cowrie lui-même inclut un plugin pour notifier via Telegram. Nous allons cependant le modifier. Par défaut, il affiche :

- `cowrie.login.success` -> quelqu'un a trouvé des identifiants et est entré.
- `cowrie.command.input` -> une commande que Cowrie sait émuler.
- `cowrie.command.failed` -> une commande que Cowrie **ne** reconnaît **pas**. Attention, cela ne veut pas dire "commande erronée" : ce sont les binaires exotiques que l'attaquant s'attendait à trouver, et ils trahissent souvent mieux son intention que les commandes normales.
- `cowrie.session.file_download` -> un fichier a été téléchargé

Et voici nos cinq modifications par rapport à l'original :

1. **La date dans chaque alerte.** Le plugin d'origine ne l'incluait pas ; avec plusieurs alertes arrivant en rafale, connaître l'heure sans aller voir le journal est important.
2. **Téléchargements enrichis.** En plus de l'URL, il inclut maintenant le **SHA256**, le fichier de destination et un lien déjà construit vers VirusTotal avec ce hash. C'est ce qui alimente directement la phase de signalement du rapport.
3. **Lien vers AbuseIPDB** sous chaque IP, pour voir le pays, l'ASN et la réputation d'un simple toucher. On procède ainsi, et non en interrogeant une API de géolocalisation depuis le honeypot lui-même, pour ne pas générer de trafic sortant supplémentaire qui concurrencerait la limite de débit de l'egress, ni ajouter de dépendances à des tiers : c'est l'opérateur qui fait la consultation depuis son téléphone, pas la machine.
4. **Il signale aussi `cowrie.session.file_upload`** (téléversements par SCP), que l'original ignorait. Un téléversement est aussi intéressant qu'un téléchargement.
5. **Il échappe le HTML de la saisie de l'attaquant.** Sans cela, une commande contenant `<` ou `>` casserait le `parse_mode=HTML` et cette alerte n'arriverait jamais.
6. **Le drapeau et le pays de chaque IP**, collés à la ligne du `Source`, qui est ce qu'on lit du coin de l'œil sur le téléphone. Cela vient d'une table sur disque, donc **cela ne coûte ni une requête ni une milliseconde d'attente** (section 3.4.4).

   <pre>
   [Cowrie vía Telnet]

   Event: cowrie.command.input
   Source: 153.117.13.106  🇵🇰 Pakistan
   Ver IP en AbuseIPDB
   </pre>

   C'est le pays où **la plage est enregistrée**, pas celui où se trouve la machine : un attaquant derrière un VPS néerlandais apparaît aux Pays-Bas. C'est pourquoi il est collé à l'IP et non présenté comme un "depuis tel pays". Et si la table manquait, l'alerte part quand même, sans drapeau : l'ornement ne peut pas faire tomber une alerte.

7. **Il tait ce qui se répète, mais pas ce qui est nouveau.** Sans cela, le canal est inutilisable : une seule IP a fini par produire **10 038 événements identiques en deux heures**. Pour chaque IP, on prévient de ses **deux premières** fois avec un même script (le compteur va par (IP, script), donc un script différent sonne de nouveau depuis zéro) et, à partir de là, on se tait, sauf si elle tape quelque chose qu'on ne lui avait jamais vu taper. Ce qui est tu n'est pas perdu : c'est compté et cela apparaît dans le résumé.

<b>Les commandes n'arrivent pas une par une.</b> Le plugin sépare les événements en deux groupes, et il vaut mieux le savoir avant de tester, sinon on croira que cela ne fonctionne pas :

- <b>Immédiats</b> (`PRIORITY_EVENTS`) : l'accès avec des identifiants corrects et les téléversements et téléchargements de fichiers.
- <b>Groupés</b> (`BATCH_EVENTS`) : `cowrie.command.input` et `cowrie.command.failed`, qui s'accumulent et sont envoyés dans un seul résumé à la fermeture de la session.

Quarante commandes en dix secondes feraient quarante messages et un téléphone inutilisable ; groupées, elles n'en font qu'un, qui permet en plus de voir toute la séquence d'un coup d'œil. La conséquence quand on teste, c'est que tant que tu restes connecté en SSH, <b>rien n'arrivera</b> des commandes : il faut fermer la session avec `exit`.

<b>Pour chaque IP, on mémorise ses commandes, et le plafond compte.</b> Pour savoir si une IP a tapé quelque chose de nouveau, on garde un hash court de chacune de ses commandes, jusqu'à `MAX_CMDS_PER_IP`. Il était à 80 et c'était peu : un bot avec un long script ne tenait pas entier dans sa propre mémoire, donc chaque passe "découvrait" des commandes déjà vues et l'alerte ne se taisait jamais. Maintenant, c'est 400. Et pour ne pas dépendre de ce nombre, si l'on a dû oublier quelque chose d'une IP, on le marque et on cesse d'affirmer que rien n'est nouveau, car sur une mémoire incomplète on ne peut pas distinguer "il ne l'a jamais fait" de "je l'ai oublié" :

<pre>
Vez 341 con este guion, callada desde la 3, suena por lo de abajo
Guion 79b8b0d62de1631d
Comandos que no le habiamos visto nunca:
</pre>

Les quatre fichiers sont arrivés avec le dépôt à la section 3.4, donc on les copie à leur place. Il n'y a rien à coller :

```bash
sudo cp "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/COWRIE/telegram_alert_cowrie.py" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/COWRIE/telegram-ban-watcher" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/COWRIE/telegram-ban-watcher.service" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/COWRIE/telegram-notification-ban" "/opt/dirtyland/Telegram Reports/"
```

Et on vérifie que les quatre sont là :

```bash
ls -la "/opt/dirtyland/Telegram Reports/"
```

Les notifications Telegram et la gestion de l'API nécessitent un chat ID et un token d'API.<br>
Quand on crée un bot avec `@BotFather` sur Telegram, il renvoie un token. S'il n'en renvoie aucun, on va le générer dans @BotFather : on exécute `/mybots`, on sélectionne celui qui nous intéresse et on suit ce qu'il nous dit.

Ensuite, le plus important, une fois qu'on l'a obtenu : il faut démarrer le chat et y écrire des choses. C'est très important. Si on ne le fait pas, le script ne fonctionnera pas, et il suffit de continuer à écrire des choses dans le chat jusqu'à ce que l'exécution du script renvoie l'ID.

Pour obtenir le "chat_id", j'ai créé un script qui l'automatise ; il est en base64, qui se décode et s'exécute. La raison pour laquelle il est en base64, c'est que visuellement il tient sur une seule ligne ; il te demande le token et il te trouve lui-même le chat_id :

```bash
bash <(echo "cmVhZCAtcCAiRW50ZXIgeW91ciBib3QgdG9rZW46ICIgVE9LRU4KaWYgWyAteiAiJFRPS0VOIiBdOyB0aGVuIGVjaG8gIlRva2VuIGlzIGVtcHR5LiI7IGV4aXQgMTsgZmkKZWNobyAiT2J0YWluaW5nIENoYXQgSUQuLi4iClJFU1BPTlNFPSQoY3VybCAtcyAiaHR0cHM6Ly9hcGkudGVsZWdyYW0ub3JnL2JvdCRUT0tFTi9nZXRVcGRhdGVzIikKQ0hBVF9JRD0kKGVjaG8gIiRSRVNQT05TRSIgfCBncmVwIC1vRSAnImNoYXQiOlx7ImlkIjotP1swLTldKycgfCB0YWlsIC0xIHwgc2VkICdzLy4qImlkIjovLycpCmlmIFsgLXogIiRDSEFUX0lEIiBdOyB0aGVuCiAgZWNobyAiRXJyb3I6IE5vIGNoYXQgZm91bmQuIFNlbmQgYSBtZXNzYWdlIHRvIHlvdXIgYm90IGZpcnN0LiIKICBleGl0IDEKZmkKZWNobyAiQ2hhdCBJRDogJENIQVRfSUQiCg==" | base64 -d)
```

Le "chat_id" est la valeur `result[0].message.chat.id`.

Une fois qu'on a à la fois le chat_id et le token, on les met dedans.

```bash
sudo nano /opt/dirtyland/Telegram\ Reports/telegram.cfg
```

**La structure du `telegram.cfg` est dans le dépôt**, dans **[TELEGRAM SCRIPTS/COWRIE/telegram.cfg.example](TELEGRAM%20SCRIPTS/COWRIE/telegram.cfg.example)**. Et évidemment, les clés d'API, les tokens ou les ID ne se partagent jamais avec personne.

Comme Python est sensible à l'indentation et que coller dans un éditeur en terminal peut l'altérer, on valide la syntaxe du fichier avant de le monter (on le fait avec le Python de l'hôte, pas avec celui du conteneur, car le fichier n'est pas encore monté dedans) :

```bash
sudo python3 -c "import ast; from pathlib import Path; ast.parse(Path('/opt/dirtyland/Telegram Reports/telegram_alert_cowrie.py').read_text()); print('sintaxis OK')"
```

On vérifiera avant toute chose que le cfg contient les tokens et que les scripts n'ont pas de fins de ligne Windows :

```bash
grep -E '^(bot_token|chat_id)' "/opt/dirtyland/Telegram Reports/telegram.cfg"; file "/opt/dirtyland/Telegram Reports/telegram-ban-watcher" "/opt/dirtyland/Telegram Reports/telegram-notification-ban"
```

On installe les deux scripts sur l'hôte :

```bash
sudo install -o root -g root -m 0755 "/opt/dirtyland/Telegram Reports/telegram-notification-ban" "/opt/dirtyland/Telegram Reports/telegram-ban-watcher" /usr/local/sbin/
```

On installe et on démarre le service :

```bash
sudo install -o root -g root -m 0644 "/opt/dirtyland/Telegram Reports/telegram-ban-watcher.service" /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now telegram-ban-watcher && sudo systemctl status telegram-ban-watcher --no-pager
```

On crée le répertoire d'écriture avec l'uid du conteneur :

```bash
CU=$(sudo ps -o uid= -p $(sudo docker inspect -f '{{.State.Pid}}' dirtyland_cowrie) | tr -d ' ') && echo "uid de Cowrie visto por el host: $CU" && sudo mkdir -p "/opt/dirtyland/Telegram Reports/state" && sudo chown "$CU" "/opt/dirtyland/Telegram Reports/state" && sudo chmod 770 "/opt/dirtyland/Telegram Reports/state" && sudo chown "$CU" "/opt/dirtyland/Telegram Reports/telegram.cfg" && sudo chmod 600 "/opt/dirtyland/Telegram Reports/telegram.cfg" && ls -la "/opt/dirtyland/Telegram Reports/"
```

<b>Activer le plugin dans `cowrie.cfg`.</b> Avoir le fichier dans le conteneur ne suffit pas : Cowrie ne charge un moteur de sortie que si sa section existe dans la configuration.

```bash
sudo nano /opt/dirtyland/cowrie/etc/cowrie.cfg
```

Et on ajoute à la fin :

```ini
[output_telegram]
enabled = true
```

On vérifie qu'elle a bien été écrite :

```bash
grep -A1 "^\[output_telegram\]" /opt/dirtyland/cowrie/etc/cowrie.cfg
```

> [!WARNING]
> <b>Le nom de la section ne se choisit pas, et il ne fonctionne pas comme on s'y attendrait.</b> Le chargeur de Cowrie (`src/twisted/plugins/cowrie_plugin.py`) fait ceci :
>
> ```python
> engine: str = x.split("_")[1]
> output = import_module(f"cowrie.output.{engine}").Output()
> ```
>
> Autrement dit, il coupe le nom de la section sur le tiret bas et garde <b>le premier morceau</b>. Une section `[output_telegram_alert_cowrie]` donnerait `engine = "telegram"` et Cowrie importerait `cowrie.output.telegram`, qui est <b>le plugin d'origine</b>, pas le nôtre. Et le pire : il ne donne aucune erreur. Le journal affiche un rassurant `Loaded output engine: telegram` alors que notre plugin n'a pas été chargé et que les alertes n'arrivent jamais.
>
> C'est pourquoi la section est simplement `[output_telegram]` et que le plugin est monté <b>par-dessus</b> le `telegram.py` d'origine (section 3.4.2.9) : sur l'hôte, le fichier garde son nom descriptif, et ce qui pointe vers le nom attendu par Cowrie, c'est le <b>chemin de destination</b> du montage. En conséquence, un module dont le nom contient des tirets bas est inatteignable pour ce chargeur.
>

La partie Telegram est répartie sur trois sections : ici, les quatre fichiers du plugin, le `telegram.cfg` avec les tokens, le service de bannissement et la boîte aux lettres `state/` ; au 3.4.2.9, les trois montages qui les mettent dans le conteneur, et <b>jusqu'à cette section les alertes n'arrivent toujours pas</b> ; au 3.4.2.10, le `cowrie.cfg` définitif. Le deuxième bot, celui qui surveille l'hôte, est indépendant de tout cela et se monte au 3.4.4.

<b>Comment le plugin sait quelles IP sont les nôtres.</b> Les plages privées, il les a écrites en dur, mais les nœuds de sortie du VPN sont des adresses publiques ordinaires. Sans eux, une vérification de notre part arrive comme s'il s'agissait d'une attaque et le bouton rouge propose de <b>bannir ton propre nœud</b>, ce qui te laisse hors de la machine.

La bonne liste est la `[blocklist]` du `config.ini`, mais ce fichier n'est pas monté dans le conteneur et ne doit pas l'être, car il contient les clés d'API. Ce qu'on fait, c'est que le reporter publie seulement la liste, sans secrets, dans `/opt/dirtyland/Telegram Reports/ips-propias.txt`, et que le plugin la lise là. Elle est réécrite à chaque passe, donc ajouter un nœud à la `[blocklist]` se propage tout seul. Le fichier n'existe pas avant la première passe du reporter (section 3.5), et ce n'est pas grave.

#### 3.4.2.8 Commandes émulées : installer le jeu complet déjà corrigé.

C'est la <b>deuxième partie de l'assainissement</b> commencé à la section 3.4.2.4. Là-bas, nous avons assaini le pickle (ce que Cowrie lit sur le disque) ; ici, nous remplaçons les <b>commandes</b>, que Cowrie génère lui-même et qui, telles qu'elles sont livrées d'origine, trahissent le leurre ou laissent fuiter des données réelles de l'hôte.

Le shell émulé implémente chaque commande comme un module Python. Les corriger une par une sur le serveur (en les extrayant avec `docker cp` et en les corrigeant avec `sed`) est lent et surtout **non reproductible** : chaque réinstallation obligerait à refaire des dizaines de correctifs à la main et à les réussir tous. C'est pourquoi le dépôt contient déjà **le jeu complet de modules corrigés** ; ici, il suffit de les placer et de les monter.

Les <b>70 fichiers</b> sont dans **[`COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE`](COWRIE%20FAKE%20ENVIRONMENT/COMANDOS%20COWRIE)** du dépôt (dans l'environnement factice, car ils en font partie : ce que l'attaquant voit en tapant une commande et ce qu'il voit en regardant un fichier doivent raconter la même histoire). Ce qu'ils corrigent, par groupe :

| Groupe | Modules | Ce qu'il corrige |
|---|---|---|
| Identité du système | `lsb_release`, `dpkg`, `systemctl`, `journalctl`, `uptime`, `systemd_detect_virt` | Cohérence avec Debian 13 + systemd ; `systemd-detect-virt` n'avoue pas le conteneur. `dpkg` **n'a pas la liste des paquets écrite en dur** : il la lit dans le fichier qu'exporte le générateur du système de fichiers (3.4.2.3), issu du même conteneur que le pickle |
| Matériel | `nproc`, `lscpu`, `lsblk`, `dmidecode`, `free`, `getconf` | Ils décrivent le même matériel que le pickle (i5-12400, 16 Go). `free` lit le `meminfo` du honeyfs et le formate comme le `procps-ng` de Debian 13 (`16Gi`, pas `16G`). `lsblk` décrit un **NVMe**, seule option cohérente avec `/proc/modules`. Et `getconf LONG_BIT` renvoie **64**, ce que regardent les droppers de Mirai pour choisir leur binaire |
| Disques et mémoire | `df`, `mount`, `top` | Les trois étaient cassés ou mentaient : `df` et `mount` donnaient `Exec format error` et `top` renvoyait une erreur de Vim. Maintenant, `df` et `mount` concordent avec `lsblk`, avec `/etc/fstab` et avec `/proc/mounts`, et `top` se dessine avec les processus du même `ps_command_output.json` que `ps aux`, se rafraîchit toutes les 3 s et quitte avec `q`. Dans l'en-tête mémoire, il y avait un espace de trop dans chacun des huit champs, car le `%9.1f` porte déjà son remplissage, et la ligne `Swap` a un point avant `avail Mem` et non une virgule : ce n'est pas une coquille, c'est ainsi |
| Éditeur | `nano` (et `pico`) | Émulation réelle, pas un message préenregistré : avant, il répondait `E558`, qui est une erreur de Vim. Il dessine l'écran de GNU nano 8.4, accepte `^O`, `^X`, `^G` et `^C`, respecte les permissions et **enregistre dans le système de fichiers factice ce que l'attaquant écrit**, donc un `cat` ultérieur le renvoie |
| Environnement de la session | `honeypot.py`, `printenv`, `env`, `set` | Les variables qu'une connexion laisse définies, mesurées sur une vraie Debian 13 en entrant par SSH et par telnet. Cowrie mettait `TMOUT=1800`, qu'aucune Debian ne met, exportait des variables de shell qui n'apparaissent pas dans `printenv`, et il lui manquait `PWD`, `SHLVL`, `MAIL`, les `SSH_*`, les `XDG_*` et le `LS_COLORS`. `printenv` n'existait même pas |
| **`apt`** | `apt`, `apt-get`, `ps`, `systemctl` | **Il n'installe rien** : il consulte ce qui est déjà installé en lisant le même fichier que `dpkg`, donc ils ne peuvent pas se contredire. Avant, il répondait `E: Unable to locate package nmap`, et nmap **est** dans Debian, donc la règle "ce qui n'y est pas ne se trouve pas" était un mensonge vérifiable justement avec les paquets qu'on demande. Maintenant, il répond ce que répond `apt` quand le verrou de dpkg est occupé, ce qui ne va même pas jusqu'à vérifier si le paquet existe ; `apt update` continue de fonctionner car il utilise un autre verrou, et c'est `unattended-upgrades` qui le tient, ajouté au `ps` et au `systemctl` pour que le PID du message existe. Nous nous écartons exprès du vrai sur un point : celui de trixie attend indéfiniment, et un leurre bloqué emporte le reste du script de l'attaquant. Et il ne lâche pas tout d'un coup, car ainsi on avait l'impression qu'il ne faisait rien : il révèle chaque ligne à mesure qu'il contacte le dépôt, avec indicateur de progression seulement s'il y a un terminal |
| **`awk`** *(refait)* | `awk` | **Le `-F` n'existait pas**, déclaré comme drapeau sans argument, donc `awk -F: '{print $2}'` ne fonctionnait d'aucune des deux façons dont on le tape. Maintenant, il comprend `-F` (un caractère est pris littéralement comme l'exige POSIX, à partir de deux c'est une expression régulière), `-v`, `-f`, `--`, les `-W` de mawk, et `NF` et `NR`. Et il a cessé de dire qu'il est GNU Awk : sous Debian 13, le `awk` par défaut est **mawk**, donc `awk --version` et `dpkg -l` se contredisaient |
| **`journalctl`** *(refait)* + **le pager** | `journalctl`, `paginador`, `systemctl` | Il renvoyait onze lignes fixes écrites à la main, toujours datées de juillet et signées `sshd` alors que l'`auth.log` d'à côté signe `sshd-session`. Maintenant, il est généré à partir de **la même source que l'`auth.log`**, donc les deux journaux ne peuvent pas raconter des histoires différentes, et il comprend `-n`, `-u`, `-r`, `-p`, `-k`, `-b`, `--since`, `--until`, `--list-boots` et `--no-pager`. Comme il sort maintenant des centaines de lignes, il a fallu le pager, et ce sont trois programmes différents : celui de systemd va avec `LESS=FRSXMK`, `less` seul utilise l'écran alternatif, et `more` vient d'util-linux et prévient avec un pourcentage en octets. Sans terminal, aucun ne pagine |
| **`/var/log/auth.log`** *(nouveau)* | `authlog` | La machine déclarait `rsyslog.service` actif et `dpkg` le donnait pour installé, mais le fichier n'existait pas, car rsyslog ne les crée qu'en tournant. Et tout le monde regarde ce fichier : celui qui entre vérifie si son accès a été noté, et beaucoup de droppers font `> /var/log/auth.log`. Il est généré à l'ouverture de la session, avec une semaine d'historique et, à la fin, l'entrée de l'attaquant lui-même, qui est celle qui convainc. Il va dans le système de fichiers et non dans le pickle, où il naîtrait correct et mentirait cinq minutes plus tard. Trois détails mesurés : horodatage ISO avec microsecondes, les connexions sont signées `sshd-session` depuis OpenSSH 9.8, et le fichier est `root:root` et non le `root:adm` de toujours |
| Ce qu'écoute la machine | `ss`, `netstat`, `ip`, `ifconfig`, `lsof` | Une seule table est lue par les deux, donc `ss` et `netstat` ne peuvent pas diverger sur ce qu'écoute la machine même s'ils l'affichent différemment, et les PID qu'ils déclarent se recoupent. **Il n'y avait pas un seul socket UDP**, avec `systemd-resolved` déclaré actif et son processus dans le `ps` ; trois choses qui ont été mesurées sur un trixie car elles ne se devinent pas : le stub va avec `%lo`, il y a un second écouteur sur `127.0.0.54` et le LLMNR du 5355 sort en v4 et en v6. Il manquait à `netstat` d'obéir à `-n` et `-p`, donc un `-tulpn` montrait `*:ssh` au lieu de `0.0.0.0:22` et oubliait la colonne `PID/Program name`, et son en-tête disait toujours "w/o servers" même s'il listait des serveurs. Il manquait à `ss` la colonne `Netid`, que le vrai affiche dès qu'on demande deux protocoles, c'est-à-dire dans le `ss -tuln` de n'importe quelle reconnaissance, et les largeurs étaient écrites en dur avec le format d'une version précédente : celui d'iproute2 6.x les calcule d'après le contenu et coupe chaque adresse sur le dernier `:`. Et `netstat` ne trahit plus l'`upstart` d'Ubuntu |
| **`sed`** *(nouveau)* | `sed` | Le deuxième plus tapé parmi ceux que nous ne savions pas exécuter, 132 utilisations en 90 jours, et il échouait avec `Exec format error` au milieu du script de l'attaquant. Il comprend `s///` avec n'importe quel délimiteur, les adresses par numéro, `$`, motif, plages et négation, `-n`, `-e`, `-i`, `-E`/`-r`, et les commandes `d p q =` ; ce qu'il ne sait pas faire, il le dit au lieu de faire semblant de l'avoir appliqué. Le détail qui ne se devine pas : `sed` utilise les BRE de POSIX, où `(` et `+` sont littéraux et `\(` et `\+` sont les métacaractères, à l'inverse de Python |
| **`openssl`** *(nouveau)* | `openssl` | Ici, il ne manquait rien, il y avait une contradiction de trop : `openssl` est tiré par `ca-certificates`, donc il existe dans le pickle et `dpkg -l` le déclare, mais l'interpréteur répondait `command not found`. Maintenant, il répond à `version`, à l'aide complète, aux condensés de `dgst` (qu'openssl n'appelle pas comme on les demande : `-sha256` s'annonce `SHA2-256`), `enc -base64`, `rand`, `prime`, `ciphers`, `list`, `s_client` et `passwd`. Les hashes de `passwd` et la clé de `genrsa` **sont réellement calculés**, car une valeur fixe serait un indice : deux exécutions donneraient la même. La seule chose à laquelle il ne répond pas est `speed`, qui décrirait les performances de l'hôte |
| **`tr`** *(nouveau)* | `tr` | La commande la plus tapée parmi celles que nous ne savions pas exécuter, 276 fois en 90 jours, devant `sed`. Et elle n'échouait pas en silence : le pickle la déclare, donc un `cat x \| tr -d '\r'` répondait `Exec format error` au milieu du pipe. Elle comprend la traduction, `-d`, `-s`, `-c`, `-t`, les classes `[:digit:]`, les plages, les échappements et les octaux. Elle travaille en octets et non en texte, car ce qui passe par là est souvent un binaire |
| **`systemctl`** | `systemctl` | Le pied de page venait d'un systemd plus ancien : le 245 écrivait `LOAD   = ...` et le 257, qui est celui que déclare notre `dpkg`, met `Legend: LOAD   -> ...` et ajoute deux lignes. Et il n'avait pas `--version` : il répondait avec la liste des unités, ce qu'il faisait avec n'importe quelle option inconnue |
| **`grep`** | `fs.py` | Il affichait l'usage **BSD** sur une machine qui prétend être une Debian avec GNU grep 3.11 ; le vrai, ce sont deux lignes, sur stderr et avec le code 2. Et un répertoire n'était pas signalé : `grep x /tmp` répondait `No such file or directory` à propos d'une chose que `ls` venait de lister. Maintenant, il dit `Is a directory`, et avec `-s` il se tait |
| **`find`** | `find` | **Il ne comprenait pas `-perm`**, et `find / -perm -4000` est *la* commande pour chercher par où escalader : le `-perm` comme le `-4000` passaient par la branche d'argument inconnu, donc il listait toute la machine. Maintenant, il comprend les trois formes de GNU find (`-4000`, `/2000`, `2755`), les formes symboliques et `-type l`, et un chemin qui n'existe pas n'est plus parcouru en silence. En plus, il bloquait la session : chaque entrée était de nouveau résolue depuis la racine, quatre parcours de l'arborescence par fichier, donc le coût croissait avec le carré de la taille et, sur un `find /`, l'attaquant partait avant qu'il ne réponde. L'arborescence est déjà en mémoire et elle n'est maintenant parcourue qu'une fois |
| **`file`** | `file`, `build-dirtyland-fs.sh`, `que_le_falta_al_senuelo.py` | Un binaire `setuid` apparaissait comme n'importe quel autre exécutable, ce qui est justement ce que regarde celui qui cherche par où escalader ; le vrai les marque (`setuid ELF 64-bit`). Il en manquait trois autres : `/tmp` s'annonce comme `sticky, directory`, un lien cassé dit `broken symbolic link to` et les périphériques donnent `character special (1/5)`. Et il y avait une incohérence inverse de l'habitude : le leurre émulait `file` alors que la Debian dont sort le pickle ne l'inclut pas, car elle est montée avec `--no-install-recommends`, donc `file /bin/su` répondait comme le vrai alors que `which file` ne le trouvait pas. On le corrige en ajoutant `file` à `PACKAGES`, et **cela exige de régénérer le pickle** ; `que_le_falta_al_senuelo.py` vérifie désormais les deux sens, ce que la machine dit avoir sans savoir l'exécuter, et ce qu'elle sait exécuter sans le déclarer |
| **Le disque, dans `stat`** | `stat` | Il écrivait `Device: 801h/2049d`, qui se décode en **`/dev/sda1`, un disque SATA**, sur une machine où `lsblk`, `df`, `/etc/fstab` et `/proc/modules` parlent de NVMe : c'était le seul à annoncer un autre disque, et maintenant un test croise les deux modules. De plus, coreutils 9 met `major,minor` en décimal, `Size:` va avec une tabulation, `Birth:` ne dit plus `-` car ext4 garde bien cette date, et dans `stat -t` le mode est en hexadécimal |
| **La ligne d'`uptime`** | `uptime`, `w`, `top` (`base.py`) | Les trois affichent la même ligne et elle était écrite trois fois, toutes trois différentes : `uptime` et `w` complétaient les heures avec un zéro là où procps complète avec une espace, `top` disait `1 days`, et aucune ne savait écrire `45 min`, qui est ce qui sort dans la première heure après le démarrage. Maintenant, c'est une seule fonction |
| **La locale** | `pstree`, `lsblk`, `systemctl` | Les trois dessinent des arbres et **les caractères sont choisis selon la locale**. La session du leurre n'exporte ni `LANG` ni aucun `LC_*`, donc elle tourne en POSIX et le dessin est en ASCII, mais nous écrivions de l'Unicode : `├─` là où il faut `|-` et le `●` de `systemctl status` là où il faut un `*`. Ils sont liés par un test : si quelqu'un ajoute un `LANG` UTF-8, le test échoue et rappelle qu'il y a trois modules à redessiner |
| Réseau | `ping` | Il était faux de quatre façons à la fois. Les statistiques étaient une chaîne fixe, la même avec six paquets qu'avec un et sans rapport avec les temps au-dessus. `localhost` mettait 50 ms avec `ttl=50`, alors que l'aller-retour local se compte en centièmes de milliseconde et que le TTL est 64. N'importe quel nom se résolvait, vers une IP inventée et différente à chaque fois. Et à une IP littérale, il ajoutait la parenthèse, qui est le format utilisé quand on lui donne un nom. Maintenant, les noms viennent du `/etc/hosts` du leurre lui-même et les statistiques sont calculées |
| Processus | `ps` (dans `base.py`), `pstree`, `pgrep` | `ps aux` sortait **sans colonne de commandes** : le gabarit remplissait la chaîne de format au lieu de la valeur, la ligne dépassait 80 colonnes avant d'arriver à `COMMAND` et `ps` coupe à la largeur du terminal. De plus, il publiait `VSZ`/`RSS` sans les diviser, les deux collés. Et `ps -ef` ne listait rien, seulement l'en-tête, car le premier argument était lu à la manière BSD et dans `-ef` il ne trouvait ni `a`, ni `x`, ni `u` : maintenant, il comprend `-e`, `-A`, `-f` et `-p PID`, qui est l'autre façon de le taper, aussi courante que `ps aux`. Les trois formats sont vérifiés octet par octet contre le procps de Debian 13, le PPID suit le même arbre que celui que raconte le reste du leurre au lieu d'en inventer un par ligne, et la session n'est plus figée dans le JSON : elle est synthétisée pour l'utilisateur qui est connecté |
| Fichiers et permissions | `ls`, `cat`, `find`, `stat`, `file`, `fs.py` (`cd`, `head`, `tail`, `grep`, `less`, `more`) | Ils appliquent de vraies permissions POSIX : chaque `/home` d'autrui est privé (`0750`) et seul root regarde dedans, alors que Cowrie d'origine ne vérifie pas les permissions de lecture. De plus, `ls -l` d'un lien le décrit au lieu de le résoudre, et `stat` prend le décalage horaire de `%z` au lieu d'avoir `+0300` écrit à la main, qui n'est juste que de mars à octobre |
| Intégrité | `md5sum`, `shasum` | `sha1/224/256/384/512sum` et `b2sum` renvoient le vrai hash ; avant, ils répondaient "Exec format error" |
| Escalade | `base.py` (`su`), `sudo`, `bash`, `bashbuiltins` | `su` demande un mot de passe et, s'il est correct, **change réellement d'identité** (utilisateur, uid, prompt, home), et `exit` ramène au précédent. `sudo` répond comme pour un non-sudoer à un utilisateur normal et exécute la commande si l'appelant est root ; avant, il demandait son mot de passe à root puis lui répondait `root is not in the sudoers file`, une impossibilité qu'on a vue dans une vraie session. Son texte d'usage venait de la branche 1.8 alors que `sudo -V` déclarait 1.9.16p2, donc la version vient maintenant de la liste de `dpkg`. Et un `sudo -V` de root, ce ne sont pas cinq lignes mais 142, avec les options de compilation, les chemins, les *defaults* de sudoers et les variables qu'il conserve : comme nous acceptons `root/root`, c'est le cas habituel, et le contenu vit dans `ayudas-comandos.json` parce que ce sont des données et non du code |
| **Les boucles** | `honeypot.py`, `bashbuiltins.py` | Le corps se répétait trois fois et c'est tout, donc `i=0; while [ $i -lt 2 ]` faisait trois tours là où il en faut deux : **le nombre de tours de toute boucle à compteur était toujours faux**, et compter, c'est ce à quoi sert un `while`. Maintenant, chaque tour renvoie le corps plus la boucle elle-même, donc la condition est réévaluée avec l'environnement déjà modifié et la boucle se termine d'elle-même ; ce qui ne se termine pas est arrêté par un plafond de cent tours. Avec cela, cinq autres sont apparus : `break` et `continue` répondaient `command not found`, un `break` relançait la boucle jusqu'à faire exploser la pile, un `if` dans le corps exécutait les deux branches car les conditionnelles étaient résolues avant le déroulage, une boucle avec quelque chose collé au `done` n'était pas une boucle, et **`algo \| while read VAR` n'existait pas**, alors que c'est ainsi qu'on parcourt un fichier ligne par ligne dans n'importe quel script : maintenant, on exécute la partie gauche et on fait un tour par ligne avec la variable définie. Et `((i++))` répondait `i++: command not found` sans faire avancer le compteur, car l'évaluateur ne savait que lire ; maintenant, il assigne aussi, et `((...))` est réécrit en `let` |
| **Ce qui était resté à moitié fait** | `bashbuiltins`, `nohup`, `cat`, `honeypot.py` | **`time` répondait `command not found`**, et cela n'arrive dans aucun bash : ce n'est pas un binaire, c'est un mot-clé du langage. **`nohup` annonçait le fichier et n'exécutait rien**, donc la dernière ligne de presque n'importe quel dropper (`nohup ./x &`) ne faisait rien et l'attaquant partait en croyant que son binaire tournait. Et une qui n'était sur aucune liste : `protocol.pp` est un seul emplacement, et exécuter quelque chose à l'intérieur le laissait pointer vers la commande intérieure, donc au retour le pipe extérieur perdait toute sa sortie et `eval echo hola \| cat` n'affichait rien. Cela arrivait avec tout ce qui relance une commande : `eval`, `command`, `builtin`, `source`, `nice`, `timeout`, `setarch` et `env` |
| **`x86_64` était une enveloppe, pas une commande** | `setarch` *(nouveau)* | Sous Debian, `/usr/bin/x86_64` est un lien vers `setarch`, et ce qu'il fait, c'est exécuter ce qu'on lui met derrière. Dix utilisations en 90 jours, et le plus probable est `x86_64 -R ./payload`, qui désactive la randomisation de l'espace d'adressage pour qu'un exploit soit fiable : sans l'émuler, la commande intérieure ne s'exécutait jamais et la chaîne se coupait là. Il y a les quatre noms qui pointent vers setarch en amd64, chacun se nommant d'après son `argv[0]` |
| **`head` ajoutait une ligne de trop** | `fs.py`, `cat` | Il découpait le fichier sur `\n` et écrivait un saut après chaque morceau, y compris le morceau vide que laisse le saut final, donc toute sortie avait une ligne vide en trop et `head -2 fichero \| wc -l` sur un fichier d'une ligne répondait 2. En tirant le fil, deux autres sont apparus : `cat -A` était accepté et ne faisait rien, alors que c'est justement ce qu'on tape pour voir si un fichier contient des tabulations là où il ne faut pas, et `cat -n` séparait avec deux espaces là où il faut une tabulation, donc un `cat -n \| cut -f2` emportait la ligne entière |
| **`/proc` du processus** | `sanitize-pickle.py`, `honeypot.py`, `cat` | `cat /proc/self/status` ne renvoyait pas une ligne, et un status vide est pire qu'un status bizarre, car il n'existe aucun Linux où il sort ainsi. Il est lu par tout ce qui veut savoir où il est tombé : s'il y a un débogueur attaché (`TracerPid`), s'il vit dans un conteneur (les `NS*`) ou quels privilèges il a (`Cap*`). Maintenant, ils sortent comme sur une vraie machine, avec `Seccomp: 0` et `NoNewPrivs: 0` là où Docker met 2 et 1, et avec le cgroup, qui est ce qui trahit vraiment un conteneur : un dropper regarde `/proc/1/cgroup` avant de s'installer et, s'il voit `/docker/...`, il fait demi-tour. **Cela exige de régénérer le pickle.** Et le propriétaire était toujours root, car le status est figé à la construction du pickle avec les données du bash de root et que le pickle est le même pour toutes les sessions : en entrant comme utilisateur normal, `id` disait `uid=1004(alyosha)` et `grep Uid:` disait `Uid: 0`, le même processus avec deux propriétaires en deux commandes consécutives. Les lignes qui dépendent de qui est entré sont corrigées **à la lecture**, et tous les lecteurs passent par là (`cat`, `grep`, `head`, `tail`, `less`, `more`), pas seulement `cat` |
| **`history` était masqué par un no-op** | `base.py`, `bashbuiltins` | Il répondait vide alors que la vraie commande existait déjà : Cowrie parcourt `command_modules` dans l'ordre et le dernier qui enregistre un nom l'emporte, donc le bon `Command_history` de `base.py` était masqué par le no-op de `bashbuiltins.py`, chargé après. Aucun test ne le détectait, car chaque module pris séparément est correct : maintenant, il y en a un qui lit les enregistrements dans l'ordre de chargement et vérifie qu'aucun no-op ne masque une commande implémentée |
| **Les téléchargements reniaient leur version** | `descargas` *(nouveau)* | `wget --version`, `curl --version` et `tar --version` échouaient, et c'est la première chose qu'on regarde, car les options changent d'une version à l'autre : un wget qui ne sait pas dire quel wget il est n'est pas un wget. Le module ne réécrit pas les trois, il hérite de ceux de Cowrie et se place seulement devant pour répondre à `--version`. Et `gzip` n'existait sous aucune forme alors que le système de fichiers le déclare : un `gzip -d payload.gz`, qui est l'étape suivant le téléchargement dans la moitié des scripts, répondait `No such file or directory` |
| **La persistance par `crontab`** | `crontab` *(refait)* | **`crontab -` bloquait la session**, alors que c'est ainsi qu'on installe une tâche depuis un script et la façon la plus utilisée de persister. Et ce qui ne bloquait pas mentait : rien n'était enregistré, donc un `crontab -` suivi de `crontab -l` répondait `no crontab for root`. Maintenant, il est écrit là où cron l'écrit (`/var/spool/cron/crontabs/USUARIO`) pour qu'un `cat` de ce chemin et le `crontab -l` racontent la même chose, avec l'en-tête de trois lignes que `crontab -l` ne montre pas |
| **`useradd` n'était pas `useradd`** | `usuarios` *(nouveau)* | L'image le faisait pointer vers la même classe qu'`adduser`, et ce sont deux programmes différents : `adduser` est l'enveloppe interactive de Debian et `useradd` le binaire de shadow, qui n'affiche ni ne demande rien. Un `useradd pepe` restait à demander un mot de passe, c'est-à-dire qu'il bloquait le script justement là où l'on crée la porte dérobée. Maintenant, les cinq de shadow sont là et ce qu'ils font est réellement écrit dans `/etc/passwd`, `/etc/group` et `/etc/shadow`, ce qui est la seule chose qui résiste à la vérification suivante : l'attaquant fait `id pepe` dans la foulée |
| **`chattr +i` et `lsattr`** | `base.py` | Un `chattr +i` suivi d'un `lsattr` se contredisaient : l'attaquant protège son implant, l'une des premières choses que fait celui qui laisse quelque chose dans `/tmp`, et le système disait qu'aucun drapeau n'était posé. `lsattr` n'existait même pas. Les vingt-deux positions ne sont pas devinées : elles ont été mesurées en posant chaque drapeau dans un conteneur avec `CAP_LINUX_IMMUTABLE` |
| **`service` décrivait une autre machine** | `service` *(refait)* | `service --status-all` répondait une liste fixe avec `cups`, `lightdm`, `bluetooth`, `avahi-daemon` et `open-vm-tools` : **un bureau Ubuntu dans une machine virtuelle VMware**, alors que la légende est un serveur Debian 13. Cela se voyait avec deux commandes consécutives, car `systemctl` n'en liste aucune et `dpkg -l` ne les déclare pas. Maintenant, la liste vient de `/etc/init.d` et l'état de la table de `systemctl` |
| **`hostname -I` changeait le nom de la machine** | `base.py` | Le pire de tout : n'importe quel argument était pris pour un nouveau nom, donc `hostname -I`, l'une des premières choses que tape celui qui vient d'entrer, laissait l'attaquant avec un prompt `root@-I:~#` pour le reste de la session. Maintenant, il comprend `-a -A -b -d -f -F -i -I -s -y` et leurs formes longues, et l'IP vient de `ip.py`, pour que `hostname -I`, `ip a` et `ifconfig` ne disent pas trois choses différentes |
| **`$$`, `$(...)` et la barre oblique inverse** | `honeypot.py` | Trois de l'interpréteur. **`echo $$` écrivait `$$`**, et ce nombre nomme la moitié des fichiers temporaires de n'importe quel script (`/tmp/.$$`) : ce qui était créé, c'était un fichier appelé littéralement `.$$`. **Une substitution `$(...)` était résolue au découpage**, avant que les affectations de sa propre ligne ne s'exécutent, donc `i=$(expr $i + 1)` n'avançait pas. Et **un opérateur échappé par une barre oblique inverse redevenait un opérateur** : dans `expr 2 \> 1`, le `2` finissait redirigé vers un fichier appelé `1` |
| **`ls` n'était pas `ls`** | `ls`, `paginador` | **Il restait en colonnes même si la sortie n'était pas un terminal**, et ce n'est pas du formatage : `ls /etc \| wc -l` comptait 29 là où il y en a 60, donc tout ce qui compte ou filtre la sortie de `ls`, qui est la façon de parcourir un répertoire depuis un script, était faux. La répartition en colonnes n'était pas la sienne non plus : il écrivait de gauche à droite alors que le vrai remplit chaque colonne vers le bas, et il séparait avec une espace au lieu de deux. Pour savoir si la sortie va vers un terminal, on regarde maintenant la table de descripteurs de Cowrie : avec `next_command`, on détectait les pipes mais pas un `> fichero` |
| **Neuf de coreutils qui manquaient** | `coreutils_mas` *(nouveau)*, `ulimit`, `env`, `uptime` | `arch`, `tty`, `stty`, `nice`, `timeout`, `realpath`, `paste`, `fold` et `expr` répondaient `No such file or directory`, ce qui est la pire façon d'échouer, car cela signifie que la machine ment : `ls -l` les montre, `which` les trouve et `dpkg -l` déclare coreutils. `expr` mérite une mention à part, car c'est celui qu'utilise toute boucle écrite avant que bash n'ait `$(( ))` et il apparaît encore dans les droppers copiés de vieux sites. De plus, `ulimit` avait tout son corps dans un `pass` et `env` ne savait que lister (`env -i orden` avalait la commande) |
| **Le code de sortie en cas d'échec** | `base.py` (mixin) et les seize modules qui en héritent | **Presque aucune commande ne le définissait** : elles écrivaient leur plainte et renvoyaient zéro, donc `cat fichero \|\| wget URL -O fichero` avalait la solution de secours et l'attaquant voyait son script continuer par la mauvaise branche, alors que tenter quelque chose et avoir un plan B, c'est la moitié de ce que fait un dropper. On le résout en un seul endroit, avec une mixin qui marque l'échec à l'écriture sur la sortie d'erreur, et l'héritage se fait à la main car certaines commandes y écrivent sans échouer (l'avertissement d'`apt`, la progression de `wget`). Le code n'est pas toujours 1 : `grep` et `sort` donnent 2. Trois en plus bloquaient ou tuaient la session : `mkdir /noexiste/x` explosait avec un `FileNotFoundError` que personne n'attrapait, `tr a b fichero` ne regardait pas le troisième opérande et restait à attendre, et `uniq` ne savait pas lire de fichiers |
| **L'expansion de `${...}`** | `honeypot.py`, `base.py`, `bashbuiltins.py` | Des formes de `${...}`, seules trois étaient comprises, et pas par conception : l'opérateur était cherché avec un `find()` et le premier qui apparaissait l'emportait. **Tout le reste s'affichait littéralement à l'écran**, ce qui est la pire façon d'échouer, car un `${V/b/X}` imprimé tel quel, aucun shell ne l'écrit. Deux disaient une chose et en faisaient une autre : `${V:=x}` renvoyait la valeur sans l'enregistrer, et `${V?msg}` s'affichait en entier alors que bash prévient et n'exécute pas la commande. Et `$#` n'arrivait même pas entier, car pour le découpeur ce dièse ouvre un commentaire : `echo $#` affichait un dollar isolé et avalait le reste de la ligne. Avec cela, les deux autres pièces de la boucle d'arguments de n'importe quel script : `set -- a b c` et `shift`, qui était un no-op silencieux |
| **`local`, `return` et l'environnement d'un groupe** | `honeypot.py`, `bashbuiltins.py` | **Chaque commande d'une parenthèse ou du corps d'une fonction se faisait sa propre copie de l'environnement**, donc `(A=1; echo $A)` affichait une ligne vide et une fonction ne pouvait pas utiliser une variable qu'elle venait elle-même d'affecter. Maintenant, le groupe partage le dictionnaire et c'est celui qui le lance qui décide s'il remonte vers l'extérieur : d'une fonction, oui ; d'une parenthèse, non. Et `local` et `return` répondaient qu'ils ne valent qu'à l'intérieur d'une fonction, même à l'intérieur d'une, donc **une fonction qui commence par `local`, la moitié de celles de n'importe quel script, ne faisait rien** |
| **`wc`** *(refait)* | `wc`, `coreutils_extra` | **Il n'affichait rien dans les deux cas normaux** : il écrivait en parcourant la liste des options, et sans options cette liste est vide, donc `wc fichero` et `algo \| wc` ne sortaient pas une ligne. Ce qu'il a fallu mesurer, c'est la largeur de la colonne, qui ne vient pas des chiffres mais de la taille en octets des entrées, et à travers un pipe cette taille ne se connaît pas à l'avance, donc coreutils en réserve sept : les mêmes nombres s'affichent différemment selon qu'ils viennent d'un fichier ou d'un `\|`. Au passage, trois versions du même paquet : `cut --version` disait coreutils 8.30, `chmod --version` 8.25 et `printenv --version` 9.7, sur la même machine et avec un `dpkg -l` qui en déclare une seule. Maintenant, elles sortent d'une fonction commune qui lit la liste de dpkg |
| **`/bin/sh` est dash** | `bash.py`, `honeypot.py` | Sous Debian, `/bin/sh` n'est pas bash, c'est dash, et Cowrie enregistrait `sh`, `bash`, `/bin/sh` et `/bin/bash` dans la même classe : taper `sh` ouvrait un shell identique à celui de la session, donc on avait l'impression que la commande ne faisait rien. Maintenant, `sh` descend à `$ `, ses erreurs sortent comme `sh: 2: asd: not found` avec le numéro de ligne, et à l'intérieur les flèches écrivent leur séquence et la touche Tab insère une tabulation, car dash n'a ni édition de ligne ni historique |
| Réalisme du shell | `honeypot.py`, `seq`, `python`, `busybox` | `$RANDOM`, prompt de continuation `>` quand une boucle reste inachevée, vrai court-circuit de `&&`/`\|\|`, et `$?` aussi incrusté dans un autre token (`echo rc=$?`), qui sortait auparavant littéralement. Il est substitué juste avant l'exécution de chaque commande et non à l'analyse de la ligne, pour que `cmd; echo $?` donne le code de `cmd` et non celui de la ligne précédente. Et `$TERM` est renseigné dans les sessions telnet, qui ne passent pas par le `getPty()` de SSH |
| Telnet | `userauth.py` | Négociation telnet à la manière de Debian (évite le softmatch "Cowrie" de nmap) |

<b>Notre `apt` n'installe rien, et c'est voulu.</b> Celui d'origine simulait l'installation et se trahissait tout seul : dans une vraie session du 30/08/2026, il a enchaîné un `Permission denied` sur le fichier de verrou pour un `apt-get update` lancé en <b>root</b>, le `-y` installé comme s'il s'agissait d'un paquet, un `.deb` `i386` sur une machine qui dit `x86_64` partout, un `Segmentation fault` en exécutant ce qui venait d'être installé et, trente secondes après la permission refusée, le même `apt-get` téléchargeant 328 kB en toute tranquillité.

Maintenant, on ne fait que consulter ce qui est déjà installé, en lisant le même `dpkg-packages.tsv` qu'utilise `dpkg`, donc les deux ne peuvent pas se contredire. Ce qui n'y est pas ne se trouve pas : celui qui demande `masscan` reçoit `Unable to locate package`, qui est la réponse d'un serveur aux dépôts réduits. Il reste une imprécision connue : trixie inclut `apt` 3.0, avec une autre présentation, et ici `apt` comme `apt-get` donnent la présentation classique.

<b>nano et les fichiers qu'on ne peut pas écrire.</b> Un éditeur qui enregistre dans `/etc/passwd` en tant qu'utilisateur normal trahit le leurre à la première tentative, et c'est l'une des premières choses qu'on essaie. Les avertissements ne sont pas rédigés par nous, ce sont ceux d'un vrai GNU nano 8.4, et ils sortent en blanc sur rouge, qui est le style que nano réserve aux problèmes de permissions.

| Situation | Ce qui s'affiche |
|---|---|
| Fichier lisible mais non inscriptible (`/etc/passwd` en utilisateur normal) | `[ Directory '/etc' is not writable ]` puis `[ File '/etc/passwd' is unwritable ]` |
| Répertoire qu'on ne peut pas traverser (`/home/mihail`, mode `0750`) | `[ Path '/home/mihail' is not accessible ]` |
| Fichier qu'on ne peut pas lire (`/etc/shadow`) | `[ Error reading /etc/shadow: Permission denied ]`, le tampon sort vide et le titre devient `New Buffer` |
| `^O` sur quelque chose qu'on ne peut pas écrire | `[ Error writing /etc/passwd: Permission denied ]`, et le fichier n'est pas touché |

La vérification se fait <b>avant</b> d'écrire. Compter sur l'échec de `fs.mkfile` ne sert à rien, car Cowrie enregistre le nœud sans regarder les permissions, et alors un utilisateur normal "enregistrait" dans `/etc/passwd` et nano répondait `Wrote 1 line`.

<b>1. Où ils sont.</b> Dans [`COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE`](COWRIE%20FAKE%20ENVIRONMENT/COMANDOS%20COWRIE), les fichiers sont répartis dans trois sous-dossiers, selon le chemin qu'ils occupent dans Cowrie :

| Sous-dossier | Fichiers | Ce que c'est |
|---|---|---|
| `commands/` | 42 | Les commandes du shell émulé |
| `shell/` | 1 (`honeypot.py`) | L'interpréteur : `$RANDOM`, `&&`, prompt de continuation |
| `telnet/` | 1 (`userauth.py`) | La négociation telnet |

Ils sont déjà sur le VPS : ils ont été téléversés avec le dépôt à la section 3.4, donc il n'y a rien à transférer. Les modules sont dans `/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE` (répartis dans `commands/`, `shell/` et `telnet/`) et la sortie de `ps` dans `/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/ps_command_output.json`.

Avant de continuer, on vérifie sur le VPS que les 70 modules et le JSON sont arrivés :

```bash
find "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE" -path '*/tests/*' -prune -o -name '*.py' -print | wc -l
ls -la "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/ps_command_output.json"
```

<b>2. Placer les modules dans `cmdpatch`.</b> Dans le dépôt, ils sont rangés selon leur chemin dans Cowrie (`commands/`, `shell/`, `telnet/`), mais sur l'hôte ils vivent tous ensemble dans un seul dossier : c'est le `docker-compose` de la section suivante qui décide vers quel chemin va chacun. Le `find` les récupère dans les trois sous-dossiers et les aplatit en un seul. Le `-prune` de `tests/` n'est pas décoratif : c'est là que vit la suite de la section 3.7.10, et sans lui elle serait copiée dans `cmdpatch/` et finirait **montée comme une commande de plus** dans Cowrie.

```bash
sudo find "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE" -path '*/tests/*' -prune -o -name '*.py' -exec cp -t /opt/dirtyland/cowrie/cmdpatch/ {} +
sudo chown root:root /opt/dirtyland/cowrie/cmdpatch/*.py
sudo chmod 644 /opt/dirtyland/cowrie/cmdpatch/*.py
```

Dans le même dossier du dépôt voyage `txtcmds/`, qui **ne sont pas des modules** : ce sont des sorties préenregistrées qui remplacent celles de Cowrie. Le `find` ci-dessus ne les récupère pas (il cherche `*.py`) et elles ne vont pas dans `cmdpatch/`, car leur chemin dans le dossier **est** le chemin du binaire dans le leurre :

```bash
sudo cp -a "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE/txtcmds/usr" /opt/dirtyland/cowrie/txtcmds/
sudo chown -R root:root /opt/dirtyland/cowrie/txtcmds
sudo find /opt/dirtyland/cowrie/txtcmds -type f -exec chmod 644 {} +
```

<b>Pourquoi elles sont nécessaires, et pourquoi elles se trouvent sous `usr/bin/`.</b> Les sorties préenregistrées de Cowrie vivent dans `txtcmds/bin/`, et sur une Debian moderne cinq d'entre elles ne se déclenchent jamais (`df`, `dmesg`, `mount`, `sync` et `stty`). Ce n'est pas qu'elles mentent, c'est que la commande se casse :

<pre>
root@pc-dev-003-ignis:~# df -h
-bash: /usr/bin/df: cannot execute binary file: Exec format error
</pre>

Le `getCommand()` de `shell/protocol.py` parcourt le `PATH` et garde le premier chemin où le fichier existe, sans résoudre les liens. Comme `/usr/bin` passe avant `/bin`, `df` se résout en `/usr/bin/df` et Cowrie cherche la sortie préenregistrée dans `txtcmds/usr/bin/df`, qui n'existe pas. Cowrie regarde dans `[honeypot] txtcmds_path` avant les siennes, donc il suffit de mettre celles que nous voulons changer.

| Fichier | Raison |
|---|---|
| `usr/bin/dmesg` | Celui de Cowrie est le démarrage d'une <b>Debian Lenny de 2009</b>, noyau 32 bits, et il contredit le `uname`, le `/proc/version` et le `/proc/cpuinfo` de la légende. Le nôtre concorde avec `dmidecode`, `lsblk`, le `meminfo` et la MAC d'`ifconfig` |
| `usr/bin/stty` | Celui de Cowrie est vide <b>et</b> dans `bin/`, d'où l'`Exec format error` |
| `usr/bin/sync` | Pareil. Il reste vide exprès, car `sync` n'affiche rien, mais le fichier doit exister |

`df`, `mount`, `getconf`, `top`, `nano` et `pico` ne se corrigent pas ici : ce sont des modules de `commands/`, car un fichier préenregistré ne voit pas les arguments et `df` et `df -h` ne donnent pas la même sortie. Ceux de `vi` et `vim` ne sont pas touchés, car là le `E558` est à sa place.

<b>3. Vérifier.</b> Il doit y avoir 70 fichiers et tous doivent compiler. Ce n'est pas une formalité : si un module a une erreur de syntaxe, Cowrie démarre **sans cette commande** et l'attaquant reçoit un "command not found" sur une commande qui devrait exister, ce qui est exactement le genre de détail qui trahit un leurre.

```bash
ls /opt/dirtyland/cowrie/cmdpatch/*.py | wc -l
sudo env PYTHONPYCACHEPREFIX=/tmp/pyc-check python3 -m py_compile /opt/dirtyland/cowrie/cmdpatch/*.py && echo "los 70 modulos compilan"
```

Le `PYTHONPYCACHEPREFIX` envoie le cache de compilation dans `/tmp` pour ne pas laisser de `__pycache__` dans `cmdpatch`, qui est le dossier qu'on parcourt ensuite pour générer les montages.

<b>4. La sortie de `ps`.</b> Cowrie ne la calcule pas : il la lit, préenregistrée, dans un `ps_command_output.json`. Celui d'origine vient d'une autre machine (il montre `mysql`, `ejabberd`, `nginx`, `exim` et même `iprt-VBoxWQueue`, qui trahit VirtualBox) et ne contient rien de notre légende. Celui du dépôt (dossier **COWRIE FAKE ENVIRONMENT**) est cohérent : systemd, NetworkManager, sshd et le `pm2`/`node` du projet d'`admin`.

```bash
sudo cp "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/ps_command_output.json" /opt/dirtyland/cowrie/etc/ps_command_output.json
python3 -c "import json; json.load(open('/opt/dirtyland/cowrie/etc/ps_command_output.json')); print('JSON OK')"
```

<b>5. Les textes de `--help`.</b> Un autre fichier de données, pour la même raison que le précédent : ce sont les aides des 49 commandes, **mesurées sur leurs vrais binaires dans une Debian 13.7**, et les mettre dans le code rendrait les deux illisibles. Sans ce fichier, rien ne casse (les commandes se comportent comme avant), mais `ls --help` recommence à lister le répertoire.

```bash
sudo cp "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/ayudas-comandos.json" /opt/dirtyland/cowrie/etc/ayudas-comandos.json
python3 -c "import json; d=json.load(open('/opt/dirtyland/cowrie/etc/ayudas-comandos.json')); print(len(d)-1, 'ayudas')"
```

<b>Presque aucune commande ne répondait à `--help`.</b> Des 47 modules existants, la plupart ignoraient l'option et faisaient leur travail : `ls --help` listait le répertoire, `nproc --help` répondait `12`, `pwd --help` lâchait `/root`. Maintenant, le crochet est en un seul endroit (`runCommand`), donc aucune ne peut être oubliée, et il passe avant l'instanciation de la commande pour que l'aide passe par le pipe : `ls --help | head -3` fonctionne. Le `-h` n'est pas touché, car dans la moitié de ces commandes il signifie autre chose (`df -h`, `ls -h`).

Les aides ont été mesurées dans un `debian:trixie` et celles d'une autre distribution ne conviennent pas : mesurées auparavant sur Ubuntu, 27 sur 46 ne correspondaient pas. Les versions des 18 paquets utilisés pour la mesure voyagent dans le JSON lui-même, dans sa clé `_medido`. Pour les refaire :

```bash
docker run -d --name debian13 debian:trixie sleep infinity
```

Ce fichier arrive avec le transfert de l'étape 2 ; si elle a été sautée, le `cp` échouera avec un `No such file or directory` et l'alternative est de l'écrire à sa destination et d'y coller le contenu du dépôt :

```bash
sudo nano /opt/dirtyland/cowrie/etc/ps_command_output.json
```

Mieux vaut le `scp` : il y a environ 1 100 lignes, et coller un tel volume dans un terminal est lent et expose à ce que le presse-papiers en coupe une partie. Quelle que soit la voie, c'est la validation avec `json.load` ci-dessus qui confirme qu'il est arrivé entier : si le JSON est tronqué, Cowrie démarre quand même mais la commande `ps` cesse de répondre.

`netstat.py` et `free.py` **sont déjà corrigés** dans le dépôt : le `netstat` pointe vers `/run/systemd/private` au lieu du `@/com/ubuntu/upstart` d'Ubuntu, et le `free` lit `/opt/honeyfs/proc/meminfo`. C'est pour ce dernier que l'assainisseur du pickle écrivait aussi dans le `honeyfs` : `free` prend la donnée sur le disque, donc les deux doivent dire 16 Go.

> [!IMPORTANT]
> Les modules sont montés en **lecture seule** par-dessus les originaux de l'image, sans la reconstruire. Remplacer ou ajouter l'un d'eux exige de recréer le conteneur (`--force-recreate`) ; un `restart` ne suffit que lorsqu'on a modifié le contenu d'un fichier déjà monté.

<b>6. Le `protocol.py` de Cowrie, corrigé.</b> Celui-ci **ne vient pas du dépôt** : c'est un fichier de l'image elle-même que nous corrigeons, comme le `mssql.py` de Dionaea. On l'extrait du conteneur, on le corrige et on le monte par-dessus.

Ce qu'il corrige se voit en une seule tentative, et on l'a vu sur la machine : tape une lettre dans `[sudo] password for root: `, efface-la, et le curseur **recule sur le prompt et mange une lettre du message**. Recommence et tout le message s'efface. Les flèches haut/bas, en plus, **affichent la commande précédente** dans l'espace du mot de passe, et `Ctrl-L` redessine la ligne de saisie avec le mot de passe dedans, en clair.

La raison : `characterReceived()` coupe bien l'écho quand un mot de passe est en cours, mais les touches d'**édition** ne sont pas définies dans cette classe (elles sont héritées de `recvline`, de Twisted, qui écrit toujours sur le terminal). Et sans écho, il n'y a rien à l'écran à effacer, donc la seule chose devant le curseur est le prompt lui-même.

On l'extrait du conteneur **toujours**, y compris lors d'un redéploiement : ainsi, si un jour la version de Cowrie monte, le correcteur trouve un fichier qu'il ne reconnaît pas et s'arrête au lieu de monter quelque chose à moitié.

```bash
sudo docker cp dirtyland_cowrie:/cowrie/cowrie-git/src/cowrie/shell/protocol.py /opt/dirtyland/cowrie/parches/protocol.py
```

```bash
sudo install -o root -g root -m 750 "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/parche-protocol.py" /opt/dirtyland/cowrie/
```

```bash
sudo /opt/dirtyland/cowrie/parche-protocol.py /opt/dirtyland/cowrie/parches/protocol.py
```

**Pourquoi un correctif et non le fichier entier.** Ce sont 547 lignes de Cowrie qui ne sont pas les nôtres et nous changeons cinq méthodes ; les apporter obligerait à les refaire à chaque mise à jour de l'image. C'est le même traitement que celui que nous réservons au `mssql.py` de Dionaea.

L'exécuter deux fois ne casse rien : il dit `ya estaba parcheado` et s'en va. Et `test_parche_protocol.py` (section 3.7.10) ne vérifie pas que le texte change : **il appuie sur les touches** contre un faux terminal, avant et après, et vérifie que pendant un mot de passe rien ne lui parvient. Le montage est ajouté par le générateur de la section suivante, qui <b>s'arrête si ce fichier manque</b> : un compose sans cette ligne démarre parfaitement et laisse le prompt se dévorer lui-même, sans aucune erreur.

#### 3.4.2.9 Le bloc définitif de Cowrie dans le docker-compose.

Ici, on termine le service `cowrie` du compose. Le service lui-même **existe déjà** depuis la section 3.4 : l'image figée, les limites, le réseau, les ports et le fuseau horaire ont été mis avec la partie 1 et on n'y touche pas. Il ne manque que ses montages : les 70 modules de commandes, le pickle, le honeyfs, la sortie de `ps` et les alertes Telegram.

Ils sont nombreux et il n'y a aucun moyen de les raccourcir : Docker n'accepte pas les jokers, et monter tout le dossier sur `commands/` **ne convient pas**, car cela masquerait les ~40 commandes que Cowrie inclut déjà et il ne resterait que les nôtres. L'alternative est de ne pas les écrire à la main.

<b>1. Générer tout le bloc `volumes`.</b> Et pas seulement les lignes des commandes, car cette partie <b>grandit</b> : aujourd'hui, il y a 68 modules et chaque commande que nous ajoutons est une ligne de plus. Les maintenir à la main signifie qu'un jour on ajoute une commande, on oublie son montage, et le conteneur continue d'exécuter celle d'origine <b>sans la moindre erreur</b>. Une erreur de ce genre ne se remarque pas avant qu'un attaquant voie une sortie qui ne colle pas.

Le script est arrivé avec le dépôt, donc il suffit de le placer dans l'arborescence :

```bash
sudo install -o root -g root -m 750 "/tmp/dirtyland-repo/DOCKER-COMPOSE/generar-volumes-cowrie.sh" "/tmp/dirtyland-repo/DOCKER-COMPOSE/montajes-dionaea.sh" /opt/dirtyland/
```

Il affiche le bloc complet avec les montages fixes, les trois de Telegram et un montage par module, en envoyant chacun vers son bon chemin (`honeypot.py` vers `shell/`, `userauth.py` vers `telnet/`, le reste vers `commands/`) :

```bash
sudo /opt/dirtyland/generar-volumes-cowrie.sh
```

Et avec `--apply`, il le remplace directement dans le `docker-compose.yml`, ce qui est le moyen de ne plus rien coller à la main :

```bash
sudo /opt/dirtyland/generar-volumes-cowrie.sh --apply
```

Avant de toucher à quoi que ce soit, il fait une copie datée, puis valide le résultat avec `docker compose config` ; si ce n'était pas valide, il restaure la copie et sort en erreur. Seul le service `cowrie` est touché. Le bloc est remplacé <b>en entier</b>, donc les montages déjà présents sont réécrits depuis leur liste fixe, et s'il en apparaissait un que le script ne connaît pas, <b>il s'arrête avant de toucher à quoi que ce soit</b> et le nomme, au lieu de l'effacer en silence. Il faut le relancer **chaque fois qu'on ajoute une commande émulée**.

> [!WARNING]
> Il vaut mieux les générer que les écrire, car l'erreur typique ne se montre pas : si un montage manque, la commande concernée continue d'exister avec la version d'origine de Cowrie et cela ne se remarque que lorsqu'elle trahit le leurre. Le cas le plus traître est <b>`__init__.py`</b> : c'est la liste des commandes que Cowrie charge au démarrage, et c'est là que `shasum` est enregistré. Si on monte les 44 fichiers "de commandes" mais qu'on oublie celui-là, `shasum.py` sera dans le conteneur et pourtant `sha256sum` ne fonctionnera toujours pas, car personne ne l'aura chargé. Il doit y avoir <b>45 lignes</b>, pas 44.

Le fuseau horaire est en double exprès, pour la raison expliquée au 3.4.2.4 : la variable `TZ` couvre les processus du conteneur et le montage de `/etc/localtime` couvre celui qui lit le fichier.

<b>2. Valider et recréer seulement Cowrie.</b> Le `--force-recreate` oblige à construire le conteneur de zéro pour qu'il relise toute la configuration ; un simple `up -d` peut décider que rien d'"essentiel" n'a changé et ne rien recréer :

```bash
cd /opt/dirtyland && sudo docker compose config >/dev/null && echo "compose OK"
sudo docker compose up -d cowrie --force-recreate
```

<b>3. Vérifier que tout est entré.</b> D'abord le décompte des montages depuis l'hôte, puis on vérifie que les correctifs se voient <b>depuis l'intérieur</b> du conteneur, ce qui est la seule façon d'écarter l'échec silencieux du montage mal écrit.

Il doit y avoir <b>70</b> montages de `cmdpatch` et <b>17</b> du reste :

```bash
sudo docker inspect dirtyland_cowrie -f '{{range .Mounts}}{{println .Source}}{{end}}' | grep -c cmdpatch
sudo docker inspect dirtyland_cowrie -f '{{range .Mounts}}{{println .Source}}{{end}}' | grep -v cmdpatch | grep -c .
```

Ces 17 sont les 16 que nous déclarons nous-mêmes (le volume `cowrie-var`, `/etc/localtime`, `cowrie.cfg`, `userdb.txt`, `fs.pickle`, le `honeyfs`, les `keys/`, les `txtcmds/`, le `ps_command_output.json`, le `dpkg-packages.tsv` de `fs/`, l'`ayudas-comandos.json`, les trois de Telegram, le dossier `geoip/` des drapeaux et le `protocol.py` corrigé de la section précédente) <br><b>plus un volume anonyme</b> que nous n'avons pas mis : `/var/lib/docker/volumes/0b698ec4d374d6d9...881a/_data`

Ce nom en hexadécimal est un <b>volume anonyme</b> : Docker le crée parce que l'image de Cowrie déclare un `VOLUME` que notre compose ne mappe pas. C'est normal et il ne faut pas l'effacer. Ceux que nous déclarons portent le préfixe du projet (`dirtyland_cowrie-var`). Pour voir quel chemin il occupe à l'intérieur et ce que déclare l'image :

```bash
sudo docker inspect dirtyland_cowrie -f '{{range .Mounts}}{{printf "%s  ->  %s  (%s)\n" .Source .Destination .Type}}{{end}}' | grep -v cmdpatch
sudo docker image inspect cowrie/cowrie:3.0.10 -f '{{json .Config.Volumes}}'
```

Le `grep -c .` de la deuxième commande n'est pas décoratif : `println` laisse une ligne vide à la fin et un `grep -vc` la compterait comme un montage de plus. Si les chiffres ne concordent pas, mieux vaut regarder la liste que deviner :

```bash
sudo docker inspect dirtyland_cowrie -f '{{range .Mounts}}{{println .Source}}{{end}}' | grep -v cmdpatch | grep . | sort
```

Si quelque chose d'inattendu apparaît, par exemple des chemins de `cowrie/output/` de l'ancien montage de `netstat.py` et `free.py`, c'est que de vieilles lignes sont restées dans le compose : maintenant, ces deux fichiers viennent de `cmdpatch`, donc il faut les effacer, sinon la même commande serait montée deux fois.

```bash
sudo docker exec dirtyland_cowrie /cowrie/cowrie-env/bin/python3 -c "
from pathlib import Path
base = Path('/cowrie/cowrie-git/src/cowrie')
print('netstat parcheado (systemd):', '/run/systemd/private' in (base/'commands/netstat.py').read_text())
print('honeypot parcheado (RANDOM):', 'RANDOM' in (base/'shell/honeypot.py').read_text())
print('shasum registrado en __init__:', 'shasum' in (base/'commands/__init__.py').read_text())
"
```

Les trois réponses doivent être `True`. La dernière est celle qui confirme que `__init__.py` est monté et que, par conséquent, les nouvelles commandes sont chargées.

```bash
sudo docker logs dirtyland_cowrie 2>&1 | grep -aE 'output engine|\[telegram\]' | tail -5
```

Deux moteurs de sortie doivent apparaître (`jsonlog` et `telegram`) <b>et en plus</b> une ligne `[telegram] tokens cargados de /opt/dirtyland/Telegram Reports/telegram.cfg`.

C'est cette deuxième ligne qui compte : c'est <b>notre</b> plugin qui l'écrit au démarrage. Si `Loaded output engine: telegram` apparaît mais qu'il n'y a aucune ligne `[telegram]`, ce qui a été chargé est le plugin d'origine et le nôtre est inerte.

> [!WARNING]
> Cowrie lit sa configuration <b>uniquement au démarrage</b>, donc un changement dans le `cowrie.cfg` ou dans un fichier monté ne prend effet qu'après avoir recréé le conteneur. Si, à un moment donné, on modifie seulement le `cowrie.cfg` sans toucher au compose, un `sudo docker restart dirtyland_cowrie` suffit pour qu'il le relise.

Si les alertes n'arrivent pas, on peut vérifier que Cowrie lit réellement la section Telegram de notre fichier de configuration :

```bash
sudo docker exec dirtyland_cowrie /cowrie/cowrie-env/bin/python3 -c "
from cowrie.core.config import CowrieConfig as c
print('enabled:', c.get('output_telegram','enabled', fallback='NO EXISTE'))
"
```

#### 3.4.2.10 Le `cowrie.cfg` définitif.

Au cours des sections précédentes, il a fallu ouvrir ce fichier plusieurs fois. Pour l'ordre et la clarté, voici la version finale et complète, qui est celle qui doit rester.

<b>Avant le fichier, les clés d'hôte.</b> Cowrie, si on ne les lui donne pas, se les fabrique lui-même avec `RSA_KEY_SIZE = 2048` écrit dans son code. Une Debian 13 avec OpenSSH 10 a la RSA à **3072 bits**, qui est la valeur par défaut de `ssh-keygen` depuis OpenSSH 8.0. C'est une différence qui se voit **sans entrer et sans s'authentifier**, avec un scan depuis l'extérieur :

<pre>
nmap -p22 -sV -A [IP VPS]
</pre>

> [!CAUTION]
> <b>Ce `nmap` ne s'exécute PAS ici : ici, il ne fonctionnerait pas.</b> C'est pour cette raison qu'il est dans un `<pre>` et non dans un bloc à copier. La machine est <b>scellée</b> pendant toute la section 3.4 et n'est exposée qu'à la <b>3.8.2</b>, donc un scan depuis l'extérieur répond pour l'instant :
>
> <pre>
> 22/tcp filtered ssh
> </pre>
>
> Et c'est ce qui est **correct** à ce stade, pas une erreur. On le montre parce que cela explique <b>pourquoi</b> les clés d'hôte générées ci-dessous sont nécessaires.

<pre>
| ssh-hostkey:
|   2048 ab:92:6a:... (RSA)      <-- Cowrie
|   3072 ...                     <-- lo que tendria un Debian 13 de verdad
</pre>

Ce n'est donc pas Cowrie qui les invente : c'est `ssh-keygen` qui les génère, le même programme qui les crée sur n'importe quelle Debian. C'est le critère de toujours, ce qui est d'origine se copie et ne s'invente pas, appliqué à la première chose que voit un scanner :

```bash
sudo ssh-keygen -q -t rsa     -f /opt/dirtyland/cowrie/keys/ssh_host_rsa_key     -N "" -C ""
sudo ssh-keygen -q -t ecdsa   -f /opt/dirtyland/cowrie/keys/ssh_host_ecdsa_key   -N "" -C ""
sudo ssh-keygen -q -t ed25519 -f /opt/dirtyland/cowrie/keys/ssh_host_ed25519_key -N "" -C ""
```

Le `-C ""` est une mesure d'hygiène des fichiers. <br>
Par défaut, `ssh-keygen` met un commentaire `usuario@maquina` avec le <b>hostname réel du VPS</b>, et il reste écrit dans le `.pub` et à l'intérieur de la clé privée. <br>
Un nmap ne le voit pas par le réseau, car le protocole envoie la clé et non l'étiquette, mais ces fichiers **sortent de la machine** dans la sauvegarde du 3.7.11. On ne les génère pas non plus avec `ssh-keygen -A`, car cette option écrit toujours dans le `/etc/ssh` de l'hôte, qui est l'endroit où vivent les clés <b>réelles</b> du serveur : les trois commandes ci-dessus font la même chose dans le répertoire du leurre.

Cowrie les lit depuis l'intérieur du conteneur, donc elles doivent lui appartenir. L'uid se demande, il ne se suppose pas, comme pour la boîte aux lettres Telegram de la section 3.4.2.7 :

```bash
CU=$(sudo ps -o uid= -p $(sudo docker inspect -f '{{.State.Pid}}' dirtyland_cowrie) | tr -d ' ') && sudo chown "$CU:$CU" /opt/dirtyland/cowrie/keys/* && sudo chmod 600 /opt/dirtyland/cowrie/keys/*_key && sudo chmod 644 /opt/dirtyland/cowrie/keys/*.pub && ls -ln /opt/dirtyland/cowrie/keys
```

Si les clés privées ne lui appartiennent pas, Cowrie démarre **sans SSH** et le signale avec un `PermissionError: [Errno 13]` sur `ssh_host_rsa_key` dans le journal ; le telnet, en revanche, continue de fonctionner, donc le leurre semble à moitié vivant.

On le vide d'abord, pour ne pas finir par mélanger le nouveau avec ce qui pouvait rester des modifications précédentes :

```bash
sudo truncate -s 0 /opt/dirtyland/cowrie/etc/cowrie.cfg
```

Et on l'ouvre pour y coller le contenu :

```bash
sudo nano /opt/dirtyland/cowrie/etc/cowrie.cfg
```

```ini
[honeypot]
hostname = pc-dev-003-ignis
contents_path = /opt/honeyfs
txtcmds_path = /opt/txtcmds
idle_timeout = 3000
interactive_timeout = 7200
internet_facing_ip = [IP VPS]

[ssh]
version = SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4
rsa_public_key = /opt/cowrie-keys/ssh_host_rsa_key.pub
rsa_private_key = /opt/cowrie-keys/ssh_host_rsa_key
ecdsa_public_key = /opt/cowrie-keys/ssh_host_ecdsa_key.pub
ecdsa_private_key = /opt/cowrie-keys/ssh_host_ecdsa_key
ed25519_public_key = /opt/cowrie-keys/ssh_host_ed25519_key.pub
ed25519_private_key = /opt/cowrie-keys/ssh_host_ed25519_key

[telnet]
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0

[shell]
filesystem = /cowrie/cowrie-git/src/cowrie/data/custom-fs.pickle
processes = /opt/ps_command_output.json
kernel_version = 6.12.74+deb13+1-amd64
kernel_build_string = #1 SMP PREEMPT_DYNAMIC Debian 6.12.74-2 (2026-03-08)
hardware_platform = x86_64
operating_system = GNU/Linux
ssh_version = OpenSSH_10.0p2 Debian-7+deb13u4, OpenSSL 3.5.6 7 Apr 2026

[output_telegram]
enabled = true
```

Clé par clé :

- `contents_path` et `filesystem` sont les deux moitiés du système de fichiers factice : le premier pointe vers le **contenu** (honeyfs) et le second vers les **métadonnées** (pickle).
- `txtcmds_path` est le dossier des sorties préenregistrées de la section 3.4.2.8. C'est un chemin de **substitution** : Cowrie regarde ici d'abord et, si la commande n'y est pas, sert la sienne. C'est pourquoi il suffit de mettre celles qu'on veut changer (`dmesg`, `stty` et `sync`) et il n'y a aucun risque de masquer les autres, contrairement à ce qui se passe avec `commands/`.
- `processes` est l'endroit d'où vient la sortie de `ps` (le `ps_command_output.json` de la section 3.4.2.8). <b>Cette clé va dans `[shell]`, pas dans `[honeypot]`</b> : Cowrie la lit avec `CowrieConfig.get("shell", "processes", fallback=None)`, et dans la mauvaise section la lecture renvoie `None` sans la moindre erreur, si bien que le leurre montre les processus d'origine, qui sont ceux d'une autre machine.
- `[ssh] version` est la bannière qu'annonce le service, et c'est **la clé que lit nmap**. La valeur **se copie d'une vraie Debian 13, elle ne se déduit pas**, car le numéro de la bannière et celui du paquet ne coïncident pas : le paquet est `1:10.0p1-7+deb13u4` (p1) et la bannière dit `10.0p2` (p2), car Debian applique les correctifs de p2 sans monter la version du paquet. On l'obtient en démarrant le sshd d'origine dans un conteneur `debian:13` et en lisant la première ligne qu'il crache :

  ```bash
  sudo docker run --rm --network host debian:13 bash -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq --no-install-recommends openssh-server >/dev/null && mkdir -p /run/sshd && ssh-keygen -A >/dev/null 2>&1 && /usr/sbin/sshd -p 2299 -o PidFile=/tmp/p && sleep 2 && exec 3<>/dev/tcp/127.0.0.1/2299 && head -1 <&3'
  ```

  <pre>
  SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4
  </pre>

  Le `--network host` est là pour la même raison qu'à la section 3.4.2.3 : sur le VPS, le trafic d'`apt` par le réseau par défaut de Docker tombe dans la `policy drop` du pare-feu.

Que cette clé soit définie est important : avec seulement `[shell] ssh_version`, `nmap -sV` continuait de signaler `OpenSSH 9.2p1 Debian 12`, la valeur par défaut de l'image, alors que le reste du leurre disait trixie.
- **Les alertes Telegram couvrent le telnet sans rien configurer, et elles disent par où l'attaquant est entré.** Cowrie marque `protocol` dans **tous** les événements d'une session (c'est `EventLog` qui le fixe en la créant), donc le plugin n'a pas à le déduire du port ni du type d'événement. Les critères sont **les mêmes** que ceux qu'avait déjà le SSH : seuls `login.success`, `file_download` et `file_upload` déclenchent une alerte, et les commandes sont groupées. Ouvrir le 23 n'augmente pas à lui seul le volume de notifications, cela ajoute seulement leur origine.

  La première ligne de l'alerte l'indique, et c'est la seule chose qu'on lit dans la notification du téléphone sans l'ouvrir :

  <pre>
  [Cowrie vía Telnet]

  Event: cowrie.login.success
  </pre>

**Le `sensor` de Cowrie figurait là, et on l'a retiré.** L'en-tête était `[Cowrie 9ee5ca58e312] via Telnet`. Cet identifiant est le champ `sensor`, qui par défaut est le <b>hostname du conteneur</b>, c'est-à-dire son id Docker, donc <b>il change à chaque `--force-recreate`</b>. Et comme il n'y a qu'un seul leurre, il ne permettait pas non plus de distinguer quoi que ce soit.

  Le résumé est **unique pour les deux protocoles** : il n'y en a pas un pour SSH et un autre pour telnet. La répartition des sessions figure sur sa première ligne :

  <pre>
  [Cowrie] Resumen --- ultimos 30 min
  Sesiones: Telnet: 91, SSH: 34
  Avisos callados: 6 (127 eventos)
  </pre>

  Cette répartition est comptée **avant** les filtres, sur `cowrie.session.connect` : si elle était comptée après, elle ne refléterait que ce qui a déjà fait l'objet d'une alerte, alors que le résumé est justement le seul endroit où l'on voit le trafic qui ne génère pas d'alerte.

  Les deux premières lignes disent des choses qu'elles ne disaient pas avant, et toutes deux pour la même raison (le résumé affirmait plus qu'il ne savait) :

  **La fenêtre est écrite.** Si en une demi-heure il n'y a rien à taire, aucun résumé n'est envoyé ; mais les compteurs continuent de tourner, donc les sessions de cette période apparaissent dans le suivant. Avant, cela n'était pas dit et on les lisait comme appartenant à leur demi-heure : 40 sessions tranquilles apparaissaient ajoutées aux 3 du bon intervalle. On ne le corrige pas en les jetant (elles seraient perdues), on le corrige en indiquant la vraie période, qui est le temps écoulé depuis le dernier résumé **envoyé**.

  **Une alerte tue compte pour une, quel que soit le nombre de commandes.** Il disait `Eventos silenciados: 127`, et 127, c'étaient les commandes des sessions qui n'avaient pas fait l'objet d'une alerte, pas les alertes. Une seule session tue de 300 commandes se lisait comme 300 messages cachés. Maintenant, les deux choses sont dites, et le grand nombre va entre parenthèses, là où il doit être.

- **`[telnet]` est actif**, et y arriver a coûté la correction de trois choses qui se tiennent les unes les autres. Elles sont écrites ici parce qu'aucune des trois ne donne une erreur qui se comprenne d'elle-même.

  **1. Le bug qui faisait tomber toutes les sessions.** Cowrie demande `DO TERMINAL-TYPE` à la connexion, et son propre `enableRemote` renvoyait `False` pour cette option. Twisted, dans la branche qui s'exécute quand le client accepte quelque chose que *nous* avons demandé, contient une assertion littérale :

  <pre>
  def will_no_true(self, state, option):
      # Peer agreed to enable an option in response to our request.
      ...
      assert self.enableRemote(
          option
      ), "enableRemote must return True in this context (for option {!r})"
  </pre>

  Autrement dit : nous demandions une option et, quand on nous l'accordait, nous la refusions. L'exception coupe la connexion au bout de 16 ms, et comme n'importe quel client telnet propose TERMINAL-TYPE, **elles tombaient toutes**. La cause de fond est celle de toujours ici : la liste des options était écrite **deux fois** ---une dans `connectionMade`, l'autre dans `enableRemote`--- et elles avaient cessé de coïncider. Maintenant, il n'y en a qu'une, `OPCIONES_SOLICITADAS`, et les deux endroits l'utilisent.

  **2. La bannière vient du honeyfs, pas de la configuration.** Cowrie fait `read_honeyfs_bytes("etc/issue.net")` ; si le fichier manque, il écrit `ERROR: Failed to load /etc/issue.net` et utilise une bannière **vide**. Un telnet de vraie Debian affiche cette ligne avant le `login:`, donc une bannière vide trahit le leurre. Le honeyfs n'avait que `/home`, si bien que `build-dirtyland-fs.sh` exporte maintenant aussi `issue`, `issue.net` et `inetd.conf` **depuis le même conteneur qui génère le pickle** : ainsi, le listing et le contenu viennent de la même photo et ne peuvent pas diverger.

  **3. Cohérence du leurre.** Une machine qui répond sur le 23 doit ressembler à une machine qui sert du telnet. On ajoute `openbsd-inetd` et `inetutils-telnetd` aux paquets du générateur (sous Debian 13, `telnetd` seul n'est qu'un paquet de transition) et `/usr/sbin/inetd` au `ps_command_output.json`. Sans cela, celui qui entrerait par le 23 verrait un `ps aux` qui n'explique pas comment il est entré.

**4. Le port doit arriver, et il n'arrivait pas.** Ce qui précède est le contenu du leurre, et rien de tout cela ne se voit de l'extérieur si le paquet n'entre pas. Il faut <b>deux</b> pièces de plus, dans deux fichiers différents, et les deux manquaient : le `docker-compose` doit publier le 23 du conteneur, et le pare-feu doit le laisser passer jusque-là.

  Les cinq pièces (la section `[telnet]`, la négociation, la bannière, la cohérence du disque et l'exposition) doivent être d'accord. Les trois premières se vérifient depuis l'intérieur ; la dernière ne se vérifie **que** depuis l'extérieur, avec le `nc` de la section 3.8.2.
- `idle_timeout = 3000` (50 minutes) ferme les sessions **inactives**. Il est lu par le shell et le telnet ; le chemin SSH, non.
- `interactive_timeout = 7200` est le plafond **absolu** de la session SSH, et il ne se réinitialise pas quand on tape. Sa valeur par défaut est de 300 secondes : sans cette ligne, toute session SSH tombe au bout de 5 minutes exactement, active ou non, et sans message. Les deux limites évitent que les sessions abandonnées par les bots concurrencent le `pids_limit` et la mémoire du conteneur.
- `internet_facing_ip` fait que Cowrie utilise l'IP publique du leurre au lieu de l'IP interne du conteneur (`172.20.0.10`), qui serait une donnée incohérente pour celui qui est dedans. **Il faut remplacer le `[IP VPS]`** : Cowrie copie la valeur telle quelle dans `SSH_CONNECTION`, et le crochet ---plus l'espace, qui laisse la variable avec cinq champs au lieu de quatre--- se voit au premier `env`.
- `[output_telegram]` est ce qui active le moteur d'alertes de la section 3.4.2.7. Le nom est imposé par le chargeur de Cowrie, qui garde le premier morceau du nom de la section ; c'est pourquoi le plugin est monté sur `telegram.py`. Les tokens ne vont pas ici, mais dans le `telegram.cfg`.

Grâce au `docker-compose`, chaque chemin du conteneur est associé à un chemin de l'hôte :

| Dans le conteneur | Sur l'hôte | Ce que c'est |
|---|---|---|
| `/opt/honeyfs` | `/opt/dirtyland/cowrie/honeyfs` | le contenu des fichiers |
| `/cowrie/cowrie-git/src/cowrie/data/custom-fs.pickle` | `/opt/dirtyland/cowrie/fs/fs.pickle` | les métadonnées du faux disque |
| `/opt/ps_command_output.json` | `/opt/dirtyland/cowrie/etc/ps_command_output.json` | la sortie de `ps` |
| `/opt/dpkg-packages.tsv` | `/opt/dirtyland/cowrie/fs/dpkg-packages.tsv` | la liste de `dpkg -l` (3.4.2.3) |
| `/opt/txtcmds` | `/opt/dirtyland/cowrie/txtcmds` | les sorties préenregistrées que nous remplaçons (3.4.2.8) |
| `/opt/cowrie-keys` | `/opt/dirtyland/cowrie/keys` | les clés d'hôte SSH |
| `/cowrie/cowrie-git/src/cowrie/commands/` | `/opt/dirtyland/cowrie/cmdpatch/` | les modules de commandes |

Comme seul le `cowrie.cfg` a été modifié, il suffit en principe que Cowrie le relise :

```bash
sudo docker restart dirtyland_cowrie
```

Et juste après, <b>on vérifie que le conteneur voit vraiment la nouvelle version</b>, et ce n'est pas de la paranoïa :

```bash
sudo docker exec dirtyland_cowrie /cowrie/cowrie-env/bin/python3 -c "
from cowrie.core.config import CowrieConfig as c
print('hostname:', c.get('honeypot','hostname'))
print('telegram:', c.get('output_telegram','enabled', fallback='NO EXISTE'))"
```

> [!WARNING]
> Si une ancienne valeur sort ici (ou `NO EXISTE` alors que la section a été écrite), le `restart` ne suffit pas et il faut recréer :
>
> ```bash
> sudo docker compose -f /opt/dirtyland/docker-compose.yml up -d cowrie --force-recreate
> ```
>
> La raison est que Docker lie le bind-mount d'un fichier isolé à l'<b>inode</b>, pas au chemin. Si l'éditeur modifie le fichier sur place, le conteneur voit le changement, mais plusieurs éditeurs, dont `nano` selon la version, écrivent un fichier temporaire et le renomment par-dessus, ce qui crée un nouvel inode que le conteneur ne suit plus. On le vérifie en comparant les deux :
>
> ```bash
> stat -c %i /opt/dirtyland/cowrie/etc/cowrie.cfg
> sudo docker exec dirtyland_cowrie /cowrie/cowrie-env/bin/python3 -c "import os; print(os.stat('/cowrie/cowrie-git/etc/cowrie.cfg').st_ino)"
> ```
>
> On utilise Python parce que l'image de Cowrie n'inclut pas `stat`. Cela concerne tous les fichiers isolés que nous montons ; les montages de répertoire (`honeyfs`, `txtcmds`, `keys`) ne sont pas touchés.

#### 3.4.2.11 Vérification interne du leurre (sans l'exposer).

La première chose est ce qu'on voit **avant d'entrer**, c'est-à-dire ce que regarde un scanner. La bannière et les clés d'hôte :

```bash
ssh-keyscan -p 2222 -T 10 172.20.0.10 2>/dev/null | ssh-keygen -lf -
```

<pre>
3072 SHA256:... [172.20.0.10]:2222 (RSA)
256 SHA256:... [172.20.0.10]:2222 (ECDSA)
256 SHA256:... [172.20.0.10]:2222 (ED25519)
</pre>

**La RSA doit indiquer 3072.** Si elle indique `2048`, Cowrie s'est fabriqué les siennes : soit les clés de la section 3.4.2.10 ne sont pas là, soit elles ne lui appartiennent pas (cherche `PermissionError` dans le journal), soit le `[ssh]` du `cowrie.cfg` ne pointe pas vers elles. Les deux autres font 256 par définition, comme sur une vraie Debian.

Et que la bannière soit celle que nous annonçons, puisque c'est ce que lit `nmap -sV` :

```bash
timeout 5 bash -c 'exec 3<>/dev/tcp/172.20.0.10/2222; head -1 <&3'
```

<pre>
SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4
</pre>

**Le suffixe entier** doit apparaître, `Debian-7+deb13u4`, pas seulement `Debian-7`. Ce `-7` est la révision du paquet Debian, pas la version de la distribution, mais tronqué, il fait dire à `nmap -sV` `OpenSSH 10.0p2 Debian 7`, qui se lit comme une Debian 7 de 2013 servant un OpenSSH de 2026. Et surtout, **il contredit le `[shell] ssh_version` de la configuration elle-même**, qui contient bien le suffixe : une chose dehors et une autre dedans.

Ensuite, le faux shell, en nous connectant directement au conteneur par son IP interne :

```bash
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null alyosha@172.20.0.10
```

<b>1. Identité et contenu.</b>

```bash
whoami
hostname
ls -la /home
cat /etc/debian_version
uname -a
cat ~/.bashrc
```

<b>2. Qu'aucune commande ne trahisse l'environnement réel.</b> Toutes doivent raconter la même histoire (Debian 13, i5-12400, 16 Go, sans trace de Docker ni du VPS) :

```bash
cat /etc/os-release
free -h
dpkg -l | wc -l
dpkg -l | grep -E ' (openssh-server|nano|inetutils-telnetd) '
cat /proc/version
cat /proc/cpuinfo
groups alyosha
ps aux
netstat -tulpn
```

Concrètement : `cat /etc/os-release` renvoie maintenant du contenu (avant, il sortait vide) ; `free -h` indique 16 Go et non les 2 Go réels ; `dpkg -l` liste **des centaines** de paquets avec les vraies versions de Debian 13 (et en particulier son `openssh-server` doit être le même `1:10.0p1-7+deb13u4` dont sort la bannière de la section précédente, et `inetutils-telnetd` doit apparaître, car c'est ce qui explique le port 23) ; `cat /proc/version` correspond à `uname -a` et n'a plus le suffixe `-cloud` ; `cat /proc/cpuinfo` montre l'Intel Core i5-12400 sans le drapeau `hypervisor` ; `groups alyosha` inclut le groupe `sudo` ; `ps aux` montre les processus de la légende (systemd, pm2, node ignis-api) et aucun processus étranger ; et `netstat` ne mentionne plus l'`upstart` d'Ubuntu.

> [!WARNING]
> Le `ps aux` mérite d'être regardé calmement, car son échec ne donne pas d'erreur. Si <b>`mysql`, `ejabberd`, `www-data`, `Debian-exim`</b> ou `iprt-VBoxWQueue` y apparaissent, Cowrie utilise son fichier d'origine au lieu du nôtre, et la cause est presque toujours la même : la clé `processes` placée dans `[honeypot]` au lieu de `[shell]`. Cowrie ne prévient pas d'une clé qu'il ne trouve pas, il charge simplement sa valeur par défaut et le leurre montre les processus d'une autre machine. Cet `iprt-VBoxWQueue` est en plus un mouchard immédiat : il annonce VirtualBox.

<b>3. Que les homes d'autrui sont privés.</b> Connectés en tant qu'`alyosha`, nous ne devons pas pouvoir regarder chez un autre utilisateur. Les quatre commandes doivent répondre "Permission denied" (si, au lieu de cela, elles listent du contenu, le problème n'est pas dans les modules mais dans le pickle : les homes seront restés en `0755`, voir 3.4.2.4) :

```bash
ls /home/admin/
cd /home/admin/
cat /home/admin/.bash_history
find /home/admin -name '*.env'
```

<b>4. Que l'escalade fonctionne.</b> `su` doit demander un mot de passe, échouer avec un mauvais et **changer d'identité** avec le bon ; en sortant, nous redevenons qui nous étions :

```bash
su root            # contraseña incorrecta -> "su: Authentication failure"
su root            # con la del userdb -> el prompt pasa a "#"
whoami
ls /home/admin/    # como root, ahora sí se ve
exit
whoami             # volvemos a alyosha
sudo -l            # responde como un no-sudoers
```

<b>5. Que le shell se comporte comme bash.</b> Ce sont les détails qu'un bot utilise pour sonder s'il y a un émulateur derrière :

```bash
echo $RANDOM       # un entero distinto cada vez (0..32767)
echo $RANDOM
sha256sum /etc/hostname
echo hola | cat
echo a && echo b   # salen las dos
false && echo b    # no sale nada
false || echo b    # sale b
noexiste && echo b # "command not found" y b NO se ejecuta
echo $?            # 127
while IFS= read -r line     # queda a medias: aparece el prompt ">" (Ctrl-C para salir)
cd /proc/; cat self/cmdline # "catself/cmdline", pegado al prompt y sin salto de línea
```

<b>De plus, tout cela devrait déjà nous être notifié sur Telegram.</b>

Le système de fichiers, les commandes et les alertes de Cowrie sont terminés et vérifiés de l'intérieur. Le honeypot reste <b>non exposé</b> à Internet.

### 3.4.3 Personnalisation de Dionaea en machine Windows.

Dionaea émule des services Windows (SMB, RPC, MSSQL) et vit sur sa propre IP, séparée de celle de Cowrie, car exposer des services Windows et un SSH Debian sur la même adresse est une incohérence détectable qui brûle plus vite la réputation de l'IP. Dans cette section, nous lui donnons une identité Windows crédible : nous réduisons ses services à ceux qui sont cohérents et nous personnalisons la bannière SMB.

#### 3.4.3.1 Réduction des services de Dionaea.

<b>Pourquoi éteindre des services au lieu de les garder tous ?</b> Plus de ports captent plus d'attaques, mais un vrai Windows n'expose pas SIP, MQTT, MongoDB et WireGuard en même temps. Chaque port incohérent accélère le moment où un scanner nous catalogue comme leurre et brûle l'IP.

Dionaea inclut dix-sept services par défaut. Pour donner de la cohérence à une machine Windows avec peu de services, nous ne gardons que ceux qu'un vrai Windows exposerait : SMB (445), RPC/epmap (135) et MSSQL (1433), plus NetBIOS (`nbns`), qui accompagne toujours SMB sur une machine Windows.

Le répertoire existe déjà (il a été créé avec l'arborescence de la section 3.4). Il suffit de le peupler, en copiant les vrais fichiers depuis le conteneur qui tourne déjà :

```bash
for s in epmap mssql nbns; do sudo docker cp "dirtyland_dionaea:/opt/dionaea/etc/dionaea/services-available/$s.yaml" "/opt/dirtyland/dionaea/services-enabled/$s.yaml"; done
```

```bash
ls -la /opt/dirtyland/dionaea/services-enabled/
```

> [!IMPORTANT]
> On copie depuis le conteneur <b>en marche</b>, et non depuis un conteneur créé à la volée avec `docker create`, car dans l'image ces fichiers <b>n'existent pas</b> : c'est l'`entrypoint` qui les génère au démarrage, et c'est la particularité de la section 3.4.3.3. Avec `docker create`, le conteneur ne démarre jamais, donc le `docker cp` répond `Could not find the file ... in container`.
>
> Ce sont <b>trois</b> fichiers et il manque le quatrième : le `smb.yaml` <b>ne se copie pas</b>, il s'écrit à la main à la section suivante, car c'est lui qui porte l'identité Windows. Et `nbns` reste même si son port n'est pas publié : une machine Windows qui parle SMB parle aussi NetBIOS, et l'avoir configuré maintient la cohérence sans rien ouvrir.
>

#### 3.4.3.2 Bannière SMB personnalisée (Windows 7 SP1).

Le `path` va entre apostrophes et avec <b>une seule</b> barre oblique inverse. Dans un scalaire YAML sans guillemets, les échappements n'existent pas, donc on finirait par annoncer deux barres, et cela, n'importe qui l'aperçoit en énumérant les partages.

<b>Pourquoi Windows 7 SP1 ?</b> C'est le système qui attire toujours le plus de malware automatisé par SMB (EternalBlue et dérivés), et le nom autogénéré (`WIN-` plus des caractères aléatoires) avec le workgroup par défaut correspond à une machine de datacenter sans lien avec personne.

Le `smb.yaml` **est fourni avec le dépôt**, dans le dossier `DIONAEA`, donc il se copie comme tout le reste et ne se tape pas :

```bash
sudo cp "/tmp/dirtyland-repo/DIONAEA/smb.yaml" /opt/dirtyland/dionaea/services-enabled/smb.yaml
sudo chown root:root /opt/dirtyland/dionaea/services-enabled/smb.yaml
sudo chmod 644 /opt/dirtyland/dionaea/services-enabled/smb.yaml
```

Son contenu, pour savoir ce qu'il annonce :

<pre>
- name: smb
  config:
    os_type: 4
    os_arch: 64
    primary_domain: WORKGROUP
    oem_domain_name: WORKGROUP
    server_name: WIN-K7M9XQ2P4RS
    native_os: Windows 7 Professional 7601 Service Pack 1
    native_lan_manager: Windows 7 Professional 6.1
    shares:
      IPC$:
        comment: Remote IPC
        type: ipc
      ADMIN$:
        comment: Remote Admin
        path: 'C:\Windows'
        type: disktree
</pre>

C'est le seul des quatre que nous apportons ; les trois autres sont ceux d'origine de Dionaea et c'est pourquoi ils ont été copiés depuis le conteneur. Même critère qu'avec l'`issue.net` de Cowrie : ce qui est d'origine se copie depuis sa source, ce qui relève de la légende, nous l'apportons du dépôt.

#### 3.4.3.3 Pourquoi le bloc de Dionaea est déjà prêt.

**Ici, il n'y a rien à modifier.** Le service `dionaea` du `docker-compose` est arrivé déjà complet avec la partie 1 du dépôt (section 3.4) : ses ports liés à `[IP VPS 2]`, la variable `DIONAEA_FORCE_INIT_CONF=1` et le montage de `services-enabled` en **lecture seule**. Cette section existe pour expliquer ces deux derniers, car aucun ne se devine et tous deux donnent des symptômes qui ne pointent pas vers leur cause.

On vérifie qu'ils sont là où il faut (en YAML, une indentation mal placée revient à n'avoir rien écrit, et le compose ne se plaint pas) :

```bash
cd /opt/dirtyland && sudo docker compose config --format json | python3 -c "import json,sys; d=json.load(sys.stdin)['services']['dionaea']; print('environment:', d.get('environment')); print('volumes:'); [print('  ', v['source'], '->', v['target'], '(ro)' if v.get('read_only') else '') for v in d['volumes']]"
```

<pre>
environment: {'DIONAEA_FORCE_INIT_CONF': '1'}
volumes:
   dionaea-var -> /opt/dionaea/var 
   /opt/dirtyland/dionaea/services-enabled -> /opt/dionaea/etc/dionaea/services-enabled (ro)
</pre>

> [!NOTE]
> <b>`DIONAEA_FORCE_INIT_CONF=1` n'est pas facultatif</b>, et la raison ne se devine pas. L'image n'inclut pas la configuration toute faite : elle la garde dans `/opt/dionaea/template/etc` et son `entrypoint.sh` la copie au démarrage, mais seulement si le répertoire de destination n'existe pas :
>
> ```sh
> test ! -d /opt/dionaea/etc/dionaea && init_etc
> ```
>
> Et voici le piège : en montant notre `services-enabled` <b>à l'intérieur</b> de ce chemin, Docker crée les répertoires parents, donc il existe déjà avant que l'entrypoint ne regarde. La condition échoue et Dionaea démarre sans `dionaea.cfg` ; la variable force la copie. Le symptôme, si elle manque, est déroutant : une boucle de redémarrage répétant `Could not read config file`, qui ne pointe pas vers la cause.
>

> [!NOTE]
> <b>Le montage est en lecture seule (`:ro`), et c'est ce qui maintient la réduction des services.</b> À <b>chaque</b> démarrage, l'entrypoint relie de nouveau les dix-sept services dans `services-enabled`. Le `:ro` l'en empêche, donc nos quatre fichiers ont toujours le dernier mot. Cela se voit dans le journal, et c'est le signe que cela fonctionne :
>
> ```bash
> cp: cannot create symbolic link './etc/dionaea/services-enabled/mysql.yaml': Read-only file system
> ```
>
> Sans le `:ro`, Dionaea relancerait SIP, MQTT, MongoDB et compagnie au premier redémarrage, défaisant la section 3.4.3.1 sans que personne ne s'en aperçoive.

Le montage est en place <b>dès le premier démarrage</b>, avec le répertoire encore vide, et Dionaea démarre quand même : l'entrypoint peuple `services-available`, qui n'est pas monté, et c'est de là que viennent les trois fichiers d'origine que nous avons copiés plus tôt. C'est pourquoi cette section ne touche pas au `docker-compose`.

Comme le compose ne change pas, il suffit de recréer Dionaea pour qu'il prenne en compte les nouveaux services :

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml up -d dionaea --force-recreate
```

#### 3.4.3.4 Ce que capture chaque port, et pourquoi.

Mesuré sur la base de Dionaea après trois mois. Les trois ports sont ouverts et avec DNAT, donc la différence vient de Dionaea lui-même :

| Port | Connexions | Binaires | Ce qu'il laisse |
|---|---|---|---|
| 445 (SMB) | 15 339 | **160** | C'est le seul module qui implémente assez du protocole pour accepter l'écriture d'un fichier |
| 1433 (MSSQL) | 287 | 0 | 93 commandes SQL. Il n'y a pas de moteur derrière, donc `xp_cmdshell` n'arrive jamais à exécuter le téléchargement |
| 135 (RPC) | 135 | 0 | 25 binds et 16 requêtes, toutes de la reconnaissance. Pas une seule tentative d'exploitation |

Que les deux derniers ne donnent pas de binaires n'est pas un défaut : ils donnent du renseignement. Sur le 1433, on voit des attaquants effacer la persistance d'autres attaquants, et toute connexion est signalée de la même façon, comme force brute et scan.

> [!CAUTION]
> Si tu interroges la base à la main, `mssql_command_cmd` est un **BLOB** : un `LIKE` contre lui ne correspond jamais et renvoie un résultat vide **en silence**. Il faut l'envelopper dans `CAST(... AS TEXT)`. Le collecteur le fait déjà.

#### 3.4.3.5 Vérification de Dionaea (sans l'exposer).

On vérifie que les trois ports sont publiés et liés à la nouvelle IP :

```bash
sudo docker port dirtyland_dionaea
sudo nft list chain ip nat DOCKER | grep -E '[IP VPS 2]'
```

Cela doit ressembler à ceci :

<pre>
135/tcp -> [IP VPS 2]:135
445/tcp -> [IP VPS 2]:445
1433/tcp -> [IP VPS 2]:1433
# Warning: table ip nat is managed by iptables-nft, do not touch!
		ip daddr [IP VPS 2] tcp dport 135 counter packets 0 bytes 0 dnat to 172.20.0.20:135
		ip daddr [IP VPS 2] tcp dport 445 counter packets 0 bytes 0 dnat to 172.20.0.20:445
		ip daddr [IP VPS 2] tcp dport 1433 counter packets 0 bytes 0 dnat to 172.20.0.20:1433
</pre>

Les trois ports publiés, chacun lié à l'IP de Dionaea, et une règle `dnat` par port pointant vers `172.20.0.20`. Ce qui <b>ne</b> doit <b>pas</b> apparaître, c'est une règle avec l'IP de Cowrie : si elle apparaît, les deux leurres partageraient une IP et la répartition par interface que nous avons montée dans le compose ne produirait pas son effet.

Des compteurs à zéro sont normaux ici : personne n'est encore arrivé, car nous sommes toujours scellés.

> [!WARNING]
> Ici, <b>`ss -tlnp` ne sert à rien</b> : rien n'apparaîtra en écoute sur cette IP, et c'est ce qui est attendu. Nous avons configuré le daemon Docker avec `"userland-proxy": false`, donc Docker <b>ne lance aucun processus qui occupe le port sur l'hôte</b> et la publication est entièrement résolue par DNAT dans `nftables`.
>
> Avec le proxy à sa valeur par défaut, tu verrais bien des sockets, mais au prix d'un processus `docker-proxy` par port et, surtout, du fait que le conteneur verrait comme origine l'IP de Docker au lieu de celle de l'attaquant. L'IP d'origine est justement la donnée que nous voulons capturer.

Pour vérifier la bannière, il nous faut des outils de fingerprint, que nous installons sur l'hôte :

```bash
sudo apt install -y nmap smbclient
```

Et on vérifie que la bannière SMB annonce la bonne identité Windows :

```bash
nmap -p 445 --script smb-os-discovery [IP VPS 2]
```

Cela doit renvoyer "Windows 7 Professional 7601 Service Pack 1", le nom "WIN-K7M9XQ2P4RS" et le workgroup "WORKGROUP".

Et **ce qui ne peut sortir sur aucun des trois ports, c'est le mot "honeypot"** :

```bash
nmap -sV --version-intensity 2 -p 135,445,1433 [IP VPS 2]
```

<pre>
135/tcp  open  msrpc?
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s?
</pre>

Les trois **non identifiés**, c'est le bon résultat. Si le 1433 dit `Dionaea honeypot MS-SQL server`, le correctif de la section 3.4 n'est pas en place : soit le fichier n'a pas été monté, soit le `sed` n'a rien remplacé. Et si le 445 disait `Dionaea honeypot smbd`, ce serait que le `smb.yaml` du 3.4.3.2 ne produit pas son effet : cette signature nmap exige le nom de machine d'origine (`HOMEUSER-` et six caractères), donc le changer est justement ce qui permet de l'esquiver.

Non identifié n'est pas la même chose que "ressemble à un Windows". nmap reconnaît un vrai Windows comme `Microsoft Windows RPC` et `Microsoft Windows 7 - 10 microsoft-ds` ; ici, il renvoie des données qui ne correspondent à aucune de ses signatures. C'est un cran au-dessus de s'annoncer comme honeypot et un cran en dessous d'un vrai Windows, et c'est jusque-là que va Dionaea, qui est à interaction faible ou moyenne : il tient l'empreinte initiale de SMB, ce que voit un scanner automatique, mais n'implémente pas une session complète, donc un `smbclient -L` échoue avec `NT_STATUS_CONNECTION_DISCONNECTED`. Dans le même ordre d'idées, `smb-protocols` montre qu'il ne parle que <b>SMBv1</b> (`NT LM 0.12`), alors qu'un vrai Windows 7 SP1 propose aussi `2.0.2` et `2.1` : ce n'est pas configurable, c'est le moteur. Et il y a une contrepartie qu'il vaut mieux ne pas "corriger", car ce qui arrive sur le 445, ce sont des bots qui cherchent EternalBlue, c'est-à-dire justement SMBv1.

Enfin, comme nous l'avons fait avec l'IP de Cowrie, on vérifie <b>depuis une machine externe</b> (pas depuis le VPS lui-même) que la nouvelle IP reste scellée :

```bash
IP2=[IP VPS 2]; for p in 445 135 1433; do nc -vz -w 3 $IP2 $p; done
```

Et sous Windows, qui n'inclut pas `nc` :

```powershell
$ip2 = '[IP VPS 2]'; foreach ($puerto in 445,135,1433) { $t = New-Object Net.Sockets.TcpClient; $abierto = $t.ConnectAsync($ip2,$puerto).Wait(3000); "{0,-16} {1,-6} {2}" -f $ip2, $puerto, $(if ($abierto) { 'ABIERTO' } else { 'cerrado o filtrado' }); $t.Close() }
```

Cela doit nous donner une erreur ! `[(tcp) timed out: Operation now in progress]`, ou `cerrado o filtrado` sur les trois si tu l'as fait depuis PowerShell.

> [!IMPORTANT]
> <b>Tout reste scellé. Dionaea n'est pas encore exposé à Internet</b>, tout comme Cowrie.

### 3.4.4 Surveillance de l'hôte réel (deuxième bot Telegram).

Ceci ne surveille pas le honeypot, cela surveille l'<b>hôte</b> qui le porte : cela confirme que l'activité du serveur est celle attendue et prévient de tout écart. Cela passe par un deuxième bot Telegram, indépendant de celui de Cowrie.

<b>1. Créer le bot et obtenir ses identifiants.</b> Comme pour celui de Cowrie, on le crée avec `@BotFather` et il faut <b>écrire quelque chose au bot</b> avant de demander le `chat_id`, sinon `getUpdates` revient vide. On réutilise le même script en base64 de la section 3.4.2.7, qui demande le token et renvoie le chat :

```bash
bash <(echo "cmVhZCAtcCAiRW50ZXIgeW91ciBib3QgdG9rZW46ICIgVE9LRU4KaWYgWyAteiAiJFRPS0VOIiBdOyB0aGVuIGVjaG8gIlRva2VuIGlzIGVtcHR5LiI7IGV4aXQgMTsgZmkKZWNobyAiT2J0YWluaW5nIENoYXQgSUQuLi4iClJFU1BPTlNFPSQoY3VybCAtcyAiaHR0cHM6Ly9hcGkudGVsZWdyYW0ub3JnL2JvdCRUT0tFTi9nZXRVcGRhdGVzIikKQ0hBVF9JRD0kKGVjaG8gIiRSRVNQT05TRSIgfCBncmVwIC1vRSAnImNoYXQiOlx7ImlkIjotP1swLTldKycgfCB0YWlsIC0xIHwgc2VkICdzLy4qImlkIjovLycpCmlmIFsgLXogIiRDSEFUX0lEIiBdOyB0aGVuCiAgZWNobyAiRXJyb3I6IE5vIGNoYXQgZm91bmQuIFNlbmQgYSBtZXNzYWdlIHRvIHlvdXIgYm90IGZpcnN0LiIKICBleGl0IDEKZmkKZWNobyAiQ2hhdCBJRDogJENIQVRfSUQiCg==" | base64 -d)
```

<b>Le `CHAT_ID` est exactement le même que celui du premier bot</b>, donc la commande ci-dessus est facultative et ne sert qu'à le confirmer. Dans une conversation privée, le `chat_id` est ton propre identifiant d'utilisateur Telegram, et ce numéro ne change pas selon le bot avec lequel tu parles.

Ce qui est différent, c'est le token, et avec lui le bot. Qu'ils partagent le numéro de chat ne mélange rien, car la conversation avec ce bot est une autre fenêtre. Et cette séparation est l'objectif : les alertes du leurre seront constantes dès qu'il sera exposé et celles de l'hôte doivent être très rares, donc, mélangées, elles se perdraient dans le bruit.

<b>2. Enregistrer les identifiants.</b> Le répertoire existe déjà, il a été créé avec l'arborescence de la section 3.4 :

```bash
sudo nano /opt/dirtyland/monitor/telegram.env
```

Le token et le chat_id du deuxième bot :

```bash
BOT_TOKEN="<TOKEN>"
CHAT_ID="<CHAT_ID>"
```

<b>3. Restreindre le fichier</b>, qui contient le token :

```bash
sudo chmod 600 /opt/dirtyland/monitor/telegram.env
sudo chown root:root /opt/dirtyland/monitor/telegram.env
ls -l /opt/dirtyland/monitor/telegram.env
```

Le résumé quotidien interroge la base de données interne de Dionaea, donc il nous faut `sqlite3` sur l'hôte :

```bash
sudo apt install -y sqlite3
```

On repère où Docker garde le volume de Dionaea sur l'hôte :

```bash
sudo docker volume inspect dirtyland_dionaea-var --format '{{ .Mountpoint }}'
```

Et, dans ce volume, le vrai chemin de la base de données :

```bash
sudo find /var/lib/docker/volumes/dirtyland_dionaea-var/_data -name '*.sqlite'
```

> [!WARNING]
> Le `find` renvoie <b>deux</b> fichiers `.sqlite`. Le bon, celui où Dionaea écrit vraiment, est celui qui se trouve dans le sous-répertoire `lib/dionaea/` :
> `/var/lib/docker/volumes/dirtyland_dionaea-var/_data/lib/dionaea/dionaea.sqlite`
> L'autre, à la racine du volume, est vide (c'est un reste de l'initialisation). C'est ce chemin qu'utilise la variable `DIONAEA_DB` dans le script du résumé quotidien.

<b>Cette base est la seule chose qui dit si Dionaea est toujours vivant</b>, et c'est pourquoi le résumé quotidien regarde à quand remonte la dernière connexion qu'elle a notée, et pas seulement combien il y en a eu aujourd'hui. Dionaea est une fois resté bloqué en boucle et n'a rien enregistré pendant cinq jours alors que tout ce qu'on regarde habituellement disait qu'il était parfait : `docker ps` donnait `Up 6 days`, le processus existait en brûlant un cœur et le DNAT continuait de compter des paquets sur le 445. Le résumé écrivait "(sin conexiones)", qui se lit comme "personne n'a attaqué aujourd'hui". Ni "est-il démarré ?" ni "le processus existe-t-il ?" ne servent à rien, car les deux étaient vrais alors que le leurre était mort pour ce à quoi il sert. Maintenant, s'il s'écoule plus de <b>6 heures</b> sans connexion notée, le résumé le dit en grand avec la commande de diagnostic écrite (`docker top dirtyland_dionaea` : si le `TIME` se compte en jours, c'est cela).

On peut vérifier le schéma de la base pour comprendre ce qu'interroge le script (la table qui nous intéresse est `connections`) :

```bash
sudo sqlite3 /var/lib/docker/volumes/dirtyland_dionaea-var/_data/lib/dionaea/dionaea.sqlite ".tables"
```

Cette interrogation de la base de Dionaea depuis l'hôte est nécessaire car Dionaea, contrairement à Cowrie, <b>ne dispose pas de plugins de sortie vers des services de messagerie</b> comme Telegram. Sa seule voie d'alerte est qu'un processus externe (notre script) lise périodiquement ses journaux.

Ils sont arrivés avec le dépôt, donc on les copie et on leur donne la permission d'exécution : la fonction d'envoi (`send-alert.sh`), la surveillance SSH en temps réel (`ssh-watch.sh`), le résumé quotidien (`daily-digest.sh`), la surveillance de Dionaea (`dionaea-watch.sh`), celle des proxys d'accès (`proxy-watch.sh`), la répétition de toutes les alertes (`probar-avisos.sh`), le disjoncteur (`breaker-watch.sh`), le quota quotidien (`cuota-watch.sh`) et la vérification des comptes du résumé (`estado-cuentas.py`).

Les deux derniers préviennent par le bot de l'hôte et non par celui du leurre : quand le disjoncteur saute, les trois plateformes d'abuse.ch cessent de publier, car elles partagent un compte, et ce n'est pas une attaque mais une panne de notre côté, qui dans le canal du honeypot se perdrait parmi des dizaines d'alertes par jour. Ils tournent toutes les 5 minutes, ne consomment de quota d'aucune API et ne parlent qu'aux changements d'état.

Les deux autres <b>ne s'exécutent pas</b>, ce sont des bibliothèques que les surveillants chargent avec `source` : `lib-ips.sh` est la définition partagée de "quelles IP sont les nôtres" et `lib-telegram.sh` celle de "comment découper un message pour que Telegram le livre en entier". Le `chmod +x` les laisse de côté exprès, car marquer comme exécutable quelque chose sans `shebang` ne fait qu'inviter à essayer de le lancer.

```bash
sudo cp "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/send-alert.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/ssh-watch.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/daily-digest.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/breaker-watch.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/cuota-watch.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/lib-ips.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/lib-paises.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/lib-telegram.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/estado-cuentas.py" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/DIONAEA/dionaea-watch.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/proxy-watch.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/probar-avisos.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/comandos-watch.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/auditd-watch.py" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/baneadas-diario.sh" /opt/dirtyland/monitor/
```

```bash
sudo chmod +x /opt/dirtyland/monitor/send-alert.sh /opt/dirtyland/monitor/ssh-watch.sh /opt/dirtyland/monitor/daily-digest.sh /opt/dirtyland/monitor/dionaea-watch.sh /opt/dirtyland/monitor/proxy-watch.sh /opt/dirtyland/monitor/probar-avisos.sh /opt/dirtyland/monitor/breaker-watch.sh /opt/dirtyland/monitor/cuota-watch.sh /opt/dirtyland/monitor/comandos-watch.sh /opt/dirtyland/monitor/estado-cuentas.py /opt/dirtyland/monitor/auditd-watch.py /opt/dirtyland/monitor/baneadas-diario.sh
```

<b>`proxy-watch.sh` surveille les relais SOCKS d'accès au VPS.</b> Toutes les 30 minutes, il demande à l'API publique de Mullvad si tes trois proxys sont toujours `active`, et prévient par le bot de l'hôte quand l'un tombe, revient ou disparaît de la liste. Le VPS ne peut pas vraiment les tester, car ils vivent dans le tunnel de Mullvad et il n'en est pas client, mais cet indicateur est exactement ce qui est passé à `false` les deux fois où un relais est tombé. Il ne parle qu'aux changements d'état.

Ce qu'il ne détecte pas, c'est un relais qui change d'IP de sortie sans se désinscrire. C'est rare, le symptôme est que tu n'entres pas, et cela se vérifie à la main depuis ton ordinateur :

```bash
curl -x socks5h://PROXY:1080 https://am.i.mullvad.net/ip
```

La liste des relais qu'il surveille vient d'un fichier, `proxys.conf`, et **elle doit être la même** que celle de ton `~/.ssh/config`. Au lieu de l'écrire une nouvelle fois à la main (ce qui revient à demander qu'un jour elles diffèrent et que le surveillant regarde des relais que tu n'utilises plus), **on la tire du `config` lui-même**.

**Depuis ton ordinateur** (pas sur le VPS), qui est l'endroit où se trouve le `config`. Sous Linux, on lit les relais et on les envoie directement au VPS :

```bash
grep -oE '[a-z0-9]([a-z0-9-]*[a-z0-9])?\.relays\.mullvad\.net' ~/.ssh/config | awk '!seen[$0]++' | ssh dirtyland 'cat > /tmp/proxys.conf'
```

Et sous Windows, la même chose avec PowerShell (il construit le fichier et le téléverse) :

```powershell
(Select-String -Path "$env:USERPROFILE\.ssh\config" -Pattern '[a-z0-9]([a-z0-9-]*[a-z0-9])?\.relays\.mullvad\.net' -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Select-Object -Unique) -join "`n" | Out-File "$env:TEMP\proxys.conf" -Encoding ascii; scp "$env:TEMP\proxys.conf" dirtyland:/tmp/proxys.conf; Remove-Item "$env:TEMP\proxys.conf"
```

Et **de retour sur le VPS**, on le met à sa place et on vérifie que tes trois relais apparaissent :

```bash
sudo install -o root -g root -m 644 /tmp/proxys.conf /opt/dirtyland/monitor/proxys.conf && rm /tmp/proxys.conf && sudo apt install -y jq && cat /opt/dirtyland/monitor/proxys.conf
```

<b>Pourquoi on le tire du `config` et on ne l'écrit pas.</b> L'alerte "SIN ACCESO" se déclenche quand tous les relais de `proxys.conf` tombent, quels qu'ils soient, mais le surveillant ne connaît que ceux qui sont dans ce fichier : un relais que tu utilises et qui n'y figure pas, personne ne le surveille. En le générant depuis le `config`, ils ne peuvent pas diverger.

`jq` sert à lire la réponse de l'API de Mullvad sans deviner. Le script a un plan B en texte au cas où il serait absent, mais il est plus fragile face à un changement de format : si `jq` est là, on utilise `jq`.

<b>Et la table des pays</b>, qui est ce qui met le petit drapeau à côté de chaque IP. Elle a son propre dossier, car le conteneur de Cowrie le monte entièrement (section 3.4.2.9) : le plugin du leurre l'utilise aussi.

```bash
sudo cp "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/geoip/paises.py" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/geoip/generar-tabla-paises.py" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/geoip/nombres.txt" /opt/dirtyland/geoip/ && sudo chmod 755 /opt/dirtyland/geoip/*.py && sudo chmod 644 /opt/dirtyland/geoip/*.txt
```

Et maintenant, **on génère les tables**. Cela prend moins d'une minute et télécharge environ 45 Mo :

```bash
sudo /opt/dirtyland/geoip/generar-tabla-paises.py
```

<pre>
tabla de paises en /opt/dirtyland/geoip:
  registro-v4.txt      150124 tramos
  registro-v6.txt      136067 tramos
  ubicacion-v4.txt     358154 tramos
  ubicacion-v6.txt     348330 tramos
</pre>

<b>Les tables ne voyagent pas dans le dépôt, et c'est voulu.</b> Ce sont des données dérivées : ce même script les produit à partir de sources publiques et la machine les refait tous les quinze jours par cron. Les versionner, ce serait 17 Mo entièrement réécrits à chaque régénération, et c'est le même critère qu'avec le `fs.pickle` et le `dpkg-packages.tsv` : ce qui est généré ne se versionne pas.

<b>Cette copie se fait après la création du conteneur (3.4.2.9), et ce n'est pas grave.</b> Le plugin charge la table la première fois qu'il doit afficher un drapeau, pas au démarrage. S'il la chargeait au démarrage, sur une installation depuis zéro il trouverait le dossier vide et resterait sans table pour toujours, car un `import` n'a lieu qu'une fois : les alertes sortiraient sans drapeau et rien ne le dirait. Un contrôle vérifie que cela reste ainsi.

On vérifie avec deux IP connues :

```bash
python3 /opt/dirtyland/geoip/paises.py 8.8.8.8 1.1.1.1 212.174.1.1 130.12.182.131 192.168.1.1
```

<pre>
8.8.8.8 🇺🇸 Estados Unidos
1.1.1.1 🇦🇺 Australia
212.174.1.1 🇹🇷 Turquia
130.12.182.131 🇸🇮 Eslovenia (bloque de 🇺🇸 Estados Unidos)
192.168.1.1
</pre>

La dernière n'a rien, et c'est correct : une IP privée n'est d'aucun pays, et en plus elle est généralement la nôtre.

Il y a deux sources parce que ce sont deux questions différentes. La <b>localisation</b> vient de [db-ip.com](https://db-ip.com), base *IP to Country Lite*, et dit où se trouve la machine, ce que répond AbuseIPDB et ce qu'attend celui qui regarde un drapeau ; l'<b>enregistrement</b> vient des cinq RIR et dit qui est le titulaire du bloc. Elles coïncident pour 92 % des IP, et là où elles divergent, c'est dans le cloud et les plages louées, qui est le profil de l'infrastructure depuis laquelle on attaque un leurre, donc l'alerte montre les deux quand elles ne coïncident pas. On consulte sur disque et jamais par le réseau, par sauts sur un fichier trié, sans consommer de quota AbuseIPDB.

> [!WARNING]
> <b>`sendMessage` a trois limites, et la dangereuse est la deuxième.</b>
>
> | Limite | Ce qui se passe en la dépassant |
> |---|---|
> | 4096 caractères de texte rendu | L'API renvoie 400 et l'échec se voit |
> | 100 *entities*, c'est-à-dire segments mis en forme | <b>Elle ne prévient pas</b> : elle répond `"ok":true`, livre le texte entier et jette en silence celles qui sont en trop, de la dernière vers l'arrière |
> | Environ 20 messages par minute au même chat | 429, et un morceau refusé n'est jamais réessayé |
>
> La deuxième a une conséquence fâcheuse : en perdant son `<code>`, l'IP de l'attaquant se retrouve isolée dans le texte, et à une IP isolée, le client Telegram ajoute un lien automatique, donc l'alerte finit par proposer un lien cliquable vers la machine de l'attaquant. D'où la règle pour écrire ces messages : <b>toute IP hostile et toute URL de téléchargement vont dans un `<code>`</b>.
>
> `lib-telegram.sh` compte les trois choses et découpe en plusieurs messages au lieu de tronquer, en répétant l'en-tête et en numérotant `(1/3)`, toujours sur un saut de ligne pour ne pas laisser un lien à moitié. Il découpe jusqu'à `TG_MAX_TROZOS`, qui vaut 4 : une rafale de mille IP ferait 25 messages, au-dessus du rythme qu'admet Telegram. Ce qui dépasse n'est pas affiché et l'alerte dit combien de lignes ont été omises, et rien n'est perdu : les connexions restent dans la base de Dionaea et les IP poursuivent leur chemin vers AbuseIPDB.

> [!CAUTION]
> <b>Tout ce qu'écrit l'attaquant est échappé avant d'être mis dans le message.</b> L'URL de téléchargement que Dionaea enregistre, c'est lui qui la choisit, et il lui suffit d'y mettre un signe inférieur à pour que Telegram réponde `400 can't parse entities`. Alors ce n'est pas la mise en forme qui se perd, <b>c'est toute l'alerte</b>, car le surveillant marque quand même l'événement comme vu : c'est une façon peu coûteuse de nous aveugler juste quand il y a quelque chose à voir. C'est pourquoi `tg_escapar` et `tg_recortar` s'appliquent à tout champ étranger, et le hash ne devient un lien que s'il est hexadécimal.
>
> Attention à un piège de bash : depuis la 5.2, un `&` isolé du côté droit de `${var//patrón/reemplazo}` signifie "le texte qui vient d'être trouvé", donc en échappant le signe inférieur à, ce `&` se développe en ce même caractère et le remplacement le laisse tel quel. L'échappement ne sert à rien et le résultat semble presque correct.

Et une note sur le bloc des malwares : <b>on regroupe par hash, et on compte les connexions distinctes, pas les lignes de la base</b>. Sans regroupement, un bot qui téléverse plusieurs fois le même fichier remplit l'alerte de répétitions. De plus, selon la version, Dionaea peut noter deux fois le même téléchargement (un incident `.hash` et un autre `.unique`), donc compter les lignes dirait "x4" là où il y a eu deux téléversements réels.

On peut le vérifier sans toucher au réseau ni consommer un appel, depuis le dépôt lui-même :

```bash
bash "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/tests/test-lib-telegram.sh"
```

Et celles des deux autres surveillants, qui ne touchent pas non plus au réseau ni à la vraie base (**18 ok** et **12 ok**, 0 échec) :

```bash
bash "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/tests/test-breaker-watch.sh"
bash "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/tests/test-cuota-watch.sh"
```

```bash
bash "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/tests/test-ssh-watch.sh"
```

```bash
python3 "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/tests/test_botones_cowrie.py"
```

<b>Un bouton "Block IP" pour chaque IP listée, et pourquoi cela ne s'emballe pas.</b> Le résumé de Cowrie montre plusieurs IP et n'avait qu'un seul bouton, celui de la plus insistante, donc au premier coup d'œil on avait l'impression qu'une seule était actionnable. Les boutons ne grandissent pas sans contrôle, car ils suivent la liste, et la liste était déjà limitée aux cinq IP les plus insistantes. Un par ligne, car l'étiquette d'une IPv6 atteint 45 caractères et deux par ligne se coupent sur un téléphone.

En dessous, il fallait corriger le fait que `_update_button` envoyait un nouveau clavier avec un seul bouton, donc appuyer sur celui d'une IP effaçait ceux des autres. Maintenant, le clavier est dérivé d'un état (`message_id -> {ip: estado}`) et il y a un seul endroit qui le dessine.

Les IP du résumé sont le lien vers AbuseIPDB, pas un `<code>` à copier. Cela reste sûr : ce que le `<code>` évitait, c'était que Telegram transforme l'IP isolée en un lien vers `http://esa-ip`, et dans un `<a>` à nous, c'est nous qui mettons la destination.

> [!WARNING]
> <b>De quelle IP `ssh-watch.sh` prévient, et pourquoi c'est un contrôle et non un détail.</b> Le nom d'utilisateur que sshd écrit dans le journal est choisi par celui qui se connecte, espaces compris, donc la ligne contient du texte de l'attaquant <b>avant</b> la vraie IP :
>
> ```
> Invalid user "admin from [IP VPS] port 22" from 203.0.113.9 port 51234
> ```
>
> En prenant la première occurrence de `from `, n'importe qui pouvait décider quelle adresse apparaît comme origine dans ton alerte. Et en y mettant une IP à toi, `marca_propia` la marquait avec `(nuestro 😇)` : l'alerte d'une intrusion étrangère passait pour une vérification de ta part. On l'ancre avec `" port "` derrière et on prend la dernière, qui est celle qu'ajoute sshd. `daily-digest.sh` fait la même chose.

Il reconstruit l'alerte cassée de ce jour-là et vérifie qu'avec l'ancien format on dépassait 100 *entities*, qu'avec l'actuel on reste à 73, que le découpage respecte les trois limites sans mentir sur ce qu'il coupe, et qu'une URL contenant des balises ne peut pas faire tomber l'alerte. Il doit sortir **54 ok et 0 échec**.

Pour répéter une vraie rafale contre la vraie base, sans attendre qu'elle se reproduise et sans modifier l'état du surveillant, `--test` accepte le nombre de connexions à regarder en arrière (40 par défaut) :

```bash
sudo /opt/dirtyland/monitor/dionaea-watch.sh --test 400
```

Il vaut la peine de le faire au moins une fois : le `--test` seul génère quatre lignes, et avec quatre lignes on ne teste rien du découpage.

Tous doivent être présents, et les exécutables appartenir à `root` :

```bash
ls -la /opt/dirtyland/monitor/
```

On teste l'envoi de base :

```bash
sudo /opt/dirtyland/monitor/send-alert.sh "Prueba de conexión del sistema de monitorización del host"
```

Le surveillant SSH en temps réel s'installe comme service systemd (et non comme tâche cron), car il doit écouter le journal en continu et réagir sur le moment, pas toutes les X minutes ; systemd, en plus, le relance tout seul s'il tombe et le démarre avec la machine :

```bash
sudo install -o root -g root -m 0644 "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/dirtyland-sshwatch.service" /etc/systemd/system/dirtyland-sshwatch.service
```

L'unité **est fournie avec le dépôt**, comme celle du surveillant de bannissements de la section 3.4.2.7, donc il n'y a pas à la taper. Son contenu, pour savoir ce qu'elle fait :

<pre>
[Unit]
Description=Dirtyland SSH watcher (Telegram alerts)
After=network.target ssh.service

[Service]
Type=simple
ExecStart=/opt/dirtyland/monitor/ssh-watch.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
</pre>

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now dirtyland-sshwatch.service
sudo systemctl status dirtyland-sshwatch.service --no-pager
```

<b>Et le surveillant de commandes.</b> Celui de SSH prévient que <b>quelqu'un est entré</b> ; celui-ci raconte <b>ce que cette personne est en train de faire</b>. Ce sont deux moitiés distinctes et aucune ne remplace l'autre : la première lit le journal de `sshd` et ne dépend pas du shell ; la seconde lit ce qui est tapé.

L'idée de fond est celle qui rend utile toute cette section : **on n'entre jamais dans cette machine**, donc il est normal que ce canal reste muet pendant des semaines. Ce silence est la preuve qu'il n'y a personne dedans. Une seule ligne est une raison de regarder.

Il y a deux pièces. La première s'installe dans `/etc/profile.d/`, et c'est elle qui note chaque commande dans le journal :

```bash
sudo install -o root -g root -m 0644 "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/registro-comandos.sh" /etc/profile.d/dirtyland-registro.sh
```

Et **il faut aussi la charger depuis `/etc/bash.bashrc`**, ce qui n'est pas un doublon par précaution : chaque endroit couvre des shells que l'autre ne voit pas. La commande est idempotente, donc on peut la répéter sans crainte :

```bash
grep -q dirtyland-registro /etc/bash.bashrc || printf '\n# Dirtyland: registro de ordenes (apartado 3.4.4)\n[ -r /etc/profile.d/dirtyland-registro.sh ] && . /etc/profile.d/dirtyland-registro.sh\n' | sudo tee -a /etc/bash.bashrc >/dev/null; grep -c dirtyland-registro /etc/bash.bashrc
```

Cela doit répondre `1`.

> [!WARNING]
> <b>Sans cette deuxième ligne, il y a un angle mort, et c'est justement le pire.</b> `/etc/profile.d/` n'est lu que par les shells de <b>login</b>, et un shell root ouvert avec `sudo su`, `sudo -s` ou `sudo bash` n'en est pas un, donc rien de ce qui est tapé dedans n'est enregistré : tu verrais `cmd=sudo su` puis un silence absolu, sans aucune erreur. Ce qui était difficile à voir, c'est que cela dépendait de la façon dont tu devenais root, car avec `sudo -i` ou `sudo su -` cela fonctionnait.
>
> Sous Debian, `/etc/profile` charge en plus `/etc/bash.bashrc`, donc un shell de login passe par les deux endroits. C'est pourquoi le fichier contient une garde `DIRTYLAND_REGISTRO` : sans elle, la même commande serait notée deux fois.

<b>Il n'a ni `#!` ni bit d'exécution, et c'est correct</b> : il ne s'exécute pas, c'est le shell qui le charge avec `source`. Il capte les commandes tapées dans un `bash` interactif <b>telles qu'elles sont écrites</b>, y compris ce qu'un auditeur d'appels système ne voit pas : les *builtins* (`cd`, `export`, `history -c`) et le pipe entier sur une seule ligne. Il ne capte pas ce qu'exécute un démon, ni un shell qui n'est pas `bash`, et celui qui a déjà un shell peut le désactiver avec `unset PROMPT_COMMAND`. C'est à cela que sert la seconde moitié.

<b>Et la seconde moitié : auditer les exécutions.</b> Ce qui précède s'appuie sur `PROMPT_COMMAND`, donc ne voit que ce qui est tapé **dans un bash**. Il ne voit ni un `sh`, ni un `python -c`, ni ce que lance un script, ni un binaire que quelqu'un téléverse et exécute, et celui qui a déjà un shell peut le retirer avec `unset PROMPT_COMMAND`.

Ceci regarde le niveau inférieur : l'appel système `execve`. Là, il n'y a aucun moyen de se cacher, car **pour exécuter quelque chose, il faut passer par lui**.

```bash
sudo apt install -y auditd audispd-plugins && sudo systemctl enable --now auditd && sudo auditctl -v
```

Et d'abord, la configuration du disque, **car le vrai risque n'est pas la taille** :

```bash
sudo sed -i -e 's/^max_log_file *=.*/max_log_file = 8/' -e 's/^num_logs *=.*/num_logs = 2/' -e 's/^max_log_file_action *=.*/max_log_file_action = ROTATE/' -e 's/^space_left_action *=.*/space_left_action = SYSLOG/' -e 's/^admin_space_left_action *=.*/admin_space_left_action = SYSLOG/' -e 's/^disk_full_action *=.*/disk_full_action = ROTATE/' -e 's/^disk_error_action *=.*/disk_error_action = SYSLOG/' /etc/audit/auditd.conf && sudo grep -E '^(max_log_file|num_logs|max_log_file_action|space_left_action|admin_space_left_action|disk_full_action|disk_error_action)' /etc/audit/auditd.conf
```

> [!WARNING]
> <b>Certaines configurations d'`auditd` ont `disk_full_action = HALT`, qui ÉTEINT la machine.</b> Sur un honeypot, c'est un déni de service servi sur un plateau : quelqu'un qui provoque assez d'événements fait tomber le serveur. Avec ce qui précède, il reste 16 Mo comme plafond (2 fichiers de 8), en rotation, et **sans aucune action qui arrête quoi que ce soit**.
>
> Et la taille n'a pas d'importance, car **le journal est un tampon de passage** : ce qui intéresse part vers Telegram, et ce qui est effacé par la rotation peut simplement être perdu.

Les règles vont dans un fichier et non dans `auditctl` à la main, car à la main **elles ne survivraient pas à un redémarrage**, et le surveillant continuerait de tourner sur un journal qui ne reçoit plus rien, sans la moindre erreur :

```bash
sudo install -o root -g root -m 0640 "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/AUDITD/dirtyland.rules" /etc/audit/rules.d/dirtyland.rules
```

Et on les charge :

```bash
sudo augenrules --load && sudo auditctl -l
```

Les deux doivent apparaître, celle de 64 et celle de 32 bits. Sans la seconde, il suffit à quelqu'un d'exécuter un binaire 32 bits pour contourner tout l'audit.

<b>La clé de tout cela, c'est l'`auid`</b> : c'est ce qui rend la règle utilisable.

L'`auid` est l'utilisateur qui **s'est authentifié**. Il est fixé au login et **ne peut plus être changé ensuite** : ni avec `sudo`, ni avec `su`, ni en entrant dans un autre interpréteur. Il est hérité par tous les processus enfants. Avec `auid>=1000`, la règle fait deux choses à la fois :

- **Elle capte tout ce que fait une personne**, y compris ce qu'elle fait après un `sudo su` (qui était justement l'angle mort de l'enregistrement du shell).
- **Et elle laisse de côté ce qui n'est pas une personne** : cron, systemd et (c'est très important) **tout ce qui se passe dans les conteneurs**, car ces processus ne viennent pas d'un login et n'ont pas d'`auid`. Sans ce filtre, chaque commande de chaque attaquant de Cowrie arriverait en double et l'alerte serait inutilisable.

Et le surveillant qui le lit et l'envoie :

```bash
sudo install -o root -g root -m 0644 "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/dirtyland-auditwatch.service" /etc/systemd/system/dirtyland-auditwatch.service
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now dirtyland-auditwatch.service && sudo systemctl is-active dirtyland-auditwatch.service
```

Pour le voir sans attendre, avec les dernières lignes du journal. **Avec `--seco`, cela sort à l'écran et rien n'est envoyé** (mesurer le volume ne devrait pas coûter une notification) :

```bash
sudo /opt/dirtyland/monitor/auditd-watch.py --test 200 --seco
```

Et sans `--seco`, la même chose mais sur le téléphone, ce qui est la façon de vérifier que toute la chaîne fonctionne :

```bash
sudo /opt/dirtyland/monitor/auditd-watch.py --test 200
```

Une alerte ressemble à ceci :

<pre>
<b>[dirtyland-auditwatch] Maquina VPS principal</b>
<b>🚨 Esto NO son los senuelos 🚨</b>
<b>3 ordenes  ---  user desde pts1, pts0</b>
<i><b>$</b> tu usuario   <b>#</b> como root   ---   <b>(+n)</b> = esa orden lanzo n programas mas por dentro</i>

<b>#</b> wc -l
<b>$</b> python3 -c import os; os.system('whoami')  <i>(+2)</i>
<b>$</b> sudo tail -60 /var/log/audit/audit.log  <i>(+1)</i>
</pre>

La première ligne dit quel service prévient et depuis quelle machine, et la deuxième que ceci n'est pas un leurre : par ce même chat arrivent les alertes de Cowrie et de Dionaea, et une alerte de "commandes exécutées" se lit très différemment selon sa provenance. Les marques `$` et `#` sont en dehors du bloc de code, car ce bloc est là pour copier la commande. Et l'alerte est envoyée quand les choses se calment, ou au bout de 2 minutes même si elles ne se calment pas, car avec la seule fenêtre de silence, le cas qui compte, quelqu'un en train de travailler dans la machine, est justement celui qui ne s'arrête pas.

<b>Un surveillant qui perd ce qu'il surveille quand on le redémarre est pire que pas de surveillant du tout, car on croit en avoir un.</b> Et les deux le faisaient : `comandos-watch.sh` suivait le journal avec `-n 0`, c'est-à-dire à partir de maintenant, et `auditd-watch.py` sautait à la fin du fichier au démarrage, donc ce qui était noté pendant que le service était arrêté se perdait sans laisser de trace. Maintenant, ils reprennent là où ils s'étaient arrêtés, avec `--cursor-file` et en notant l'inode et l'octet dans `auditwatch.pos`.

<b>Les entrailles d'une commande sont repliées, et le `(+n)` dit combien.</b> auditd montre chaque `execve`, y compris ce qu'un programme lance en interne : un seul `augenrules --load`, c'en sont treize, et sans repli, six commandes tapées sortaient sur 32 lignes. L'arbre `pid`/`ppid` seul ne suffit pas, car replier tout descendant ferait qu'un `sudo su` emporterait tout ce qui est tapé ensuite dans le shell root, ce qui est justement ce qu'on veut le plus voir. On regarde donc aussi le temps : un enfant qui apparaît dans les 2 secondes fait partie de cette commande. C'est une heuristique, mais elle ne cache rien en silence, car chaque commande indique combien de programmes ont été repliés dedans.

> [!CAUTION]
> <b>Un journal d'exécutions finit par contenir des secrets.</b> C'est arrivé le jour même où il a été monté : `send-alert.sh` passait le token du bot en argument de `curl`, auditd enregistre les arguments de chaque programme, et le token est apparu publié dans l'alerte Telegram elle-même. Il a fallu le révoquer. Maintenant, le token passe par l'entrée standard de `curl` avec `--config`, et il y a deux défenses de plus :
>
> - <b>Ce qui est à nous ne s'alerte pas lui-même.</b> On écarte tout ce qui mentionne `send-alert.sh`, `api.telegram.org` ou `dirtyland-cmd`. En plus des secrets, cela coupe une boucle, car l'alerte est envoyée avec `send-alert.sh`, qui exécute `curl` avec tout le texte en argument.
> - <b>Censure par précaution</b> : tokens de bot, `api_key=`, `Authorization:` et le mot de passe collé à un `-p`, ce dernier seulement dans les clients de base de données, là où ce motif a ce sens.
>
> Trop censurer cache justement ce qu'on venait voir, donc on préfère rester en deçà, et cela ne couvre pas tout l'imaginable : si tu tapes une clé dans une commande, considère-la comme compromise et change-la.

**Les deux journaux restent, et ce n'est pas de la redondance** : chacun voit ce que l'autre ne peut pas voir.

| | `dirtyland-cmdwatch` | `dirtyland-auditwatch` |
|---|---|---|
| **D'où il lit** | `PROMPT_COMMAND` du shell, via le journal | L'appel système `execve`, via `auditd` |
| **Ce qu'il montre** | La **ligne telle qu'elle a été écrite** | **Chaque programme** qui s'exécute |
| Un alias (`ls`) | `ls` | `ls --color=auto` |
| Un pipe | Une seule ligne | Un programme par segment |
| Les *builtins* (`cd`, `exit`, `export`) | **Oui** | **Non** : ils n'exécutent rien, donc il n'y a pas d'`execve` |
| `sh`, `python -c`, un binaire isolé | **Non** | **Oui** |
| Ce que lance un script en interne | **Non** | **Oui**, replié avec `(+n)` |
| Si quelqu'un fait `unset PROMPT_COMMAND` | **Il cesse de voir** | Il continue de voir |

C'est pourquoi **`exit` n'apparaît que dans l'un et `clear_console` que dans l'autre**, et ce n'est un défaut d'aucun des deux : c'est la différence entre *ce que tu as écrit* et *ce qui s'est passé*. Les commandes sont regroupées pendant <b>20 secondes</b> avant envoi et tronquées à <b>40 lignes</b> par message, car un seul `apt install`, ce sont des centaines, et une alerte de centaines de lignes ne se lit pas. Les seuils se règlent avec `AUDIT_VENTANA` et `AUDIT_MAX_LINEAS`.

<b>On note à deux moments, et il faut les deux.</b> Le normal est avant chaque *prompt* ; l'autre, à la sortie du shell, car sans lui on perdait la dernière commande de chaque session, qui est justement ce que quelqu'un fait avant de partir. Et le premier déclenchement ne note rien, il prend seulement note de l'endroit où en était l'historique : en ouvrant un shell, bash charge `~/.bash_history`, et sans cette garde la dernière ligne d'une session précédente était notée comme venant d'être exécutée.

Il est vérifié sur une vraie Debian 13 qu'il <b>ne touche pas au `$?` de l'opérateur</b> : avec l'enregistrement en place et sans lui, `false; echo $?` renvoie la même chose. S'il le changeait, quiconque regarderait son propre code de sortie verrait le nôtre.

La seconde est le service qui regroupe ce qui a été noté et l'envoie :

```bash
sudo install -o root -g root -m 0644 "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/dirtyland-cmdwatch.service" /etc/systemd/system/dirtyland-cmdwatch.service
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now dirtyland-cmdwatch.service
sudo systemctl status dirtyland-cmdwatch.service --no-pager
```

<b>Pourquoi il regroupe au lieu d'envoyer une alerte par commande.</b> Une alerte par ligne est inutilisable : dès que quelqu'un entre et travaille dix minutes, le téléphone est submergé et on cesse de lire. On rassemble ce qui arrive et on l'envoie d'un bloc dès qu'il y a une pause de 20 s, ou avant si 25 commandes s'accumulent, et on regroupe par session (utilisateur, origine et terminal), car mélanger les commandes de deux personnes dans un même message serait justement l'erreur qui rend l'alerte inutile. Le répertoire n'est montré que lorsqu'il change et le code de sortie seulement s'il n'est pas `0`.

Pour le tester sans attendre personne, il suffit d'ouvrir une autre session et de taper quelque chose :

```bash
logger -t dirtyland-cmd -p authpriv.notice -- "user=prueba tty=pts/9 from=127.0.0.1 pwd=/tmp rc=0 cmd=echo prueba del vigilante"
```

En moins d'une demi-minute, une alerte `[Host] 1 orden en la maquina principal` doit arriver.

<b>La section "¿Me han baneado?"</b> ouvre le résumé, car c'est la première chose qu'on veut savoir. Elle est générée par `estado-cuentas.py`, et avant de se fier au "No", il faut savoir ce qu'elle vérifie :

Elle fait <b>une requête authentifiée</b> à chaque plateforme et regarde si l'identifiant est toujours accepté : un `401` ou un `403`, c'est ce qui arrive quand un compte est fermé, et cela se détecte le jour même. Ce qu'elle ne peut pas voir, c'est un compte qui peut toujours lire mais dont la publication est restreinte ; elle donne donc <b>deux signaux</b> et non un : le second est notre propre disjoncteur, qui, s'il a sauté, signifie qu'abuse.ch rejetait nos envois, et il prévient généralement avant le `401`.

<pre>
🛐 Todo en orden
✅ AbuseIPDB: No me han baneado  (HTTP 200)
✅ VirusTotal: No me han baneado  (HTTP 200)
✅ abusech: No me han baneado  (query_status=hash_not_found)

Mis perfiles
MalwareBazaar · ThreatFox · AbuseIPDB · VirusTotal
</pre>

**`hash_not_found` est la bonne réponse**, même si cela sonne comme une erreur. On demande le hash d'EICAR, qui n'est pas dans MalwareBazaar exprès : ce qu'on veut savoir, ce n'est pas s'il connaît ce fichier, c'est s'il <b>accepte notre identifiant</b>. Un compte sanctionné répond `unauthorized` ou `illegal_auth_key`, et alors l'alerte dit que oui, nous avons été bannis.

On met `abusech` et non `abuse.ch` exprès : Telegram transforme en lien tout ce qui a la forme d'un domaine, et dans un message dont le sujet est de savoir si nous avons été bannis, une étiquette bleue et soulignée prête à confusion. Ni le `<code>` ni un caractère de largeur nulle ne l'évitent ; retirer le point est la seule chose qui fonctionne.

Les trois requêtes sont en lecture et consomment un appel par jour de chaque quota, 1 sur 1000 sur AbuseIPDB et 1 sur 500 sur VirusTotal : un prix raisonnable pour l'apprendre le jour même plutôt que trois semaines plus tard. Les liens viennent de la section `[perfiles]` du `config.ini`, qui se remplit à la section <b>3.5.5</b> ; ceux qui ont encore leur marqueur ne sont pas affichés.

On peut la lancer seule pour la tester :

```bash
sudo python3 /opt/dirtyland/monitor/estado-cuentas.py
```

Le résumé quotidien est programmé avec cron à 06:00 UTC, ce qui équivaut, à l'heure espagnole, à 08:00 AM en été et 7 en hiver. 

<p>Si l'hôte n'a pas cron, on l'installe :</p>

```bash
sudo apt install -y cron && sudo systemctl enable --now cron
```

Et les tâches se mettent en place avec ceci, qui **n'ouvre aucun éditeur** :

```bash
sudo install -o root -g root -m 750 "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/cron-dirtyland.sh" /opt/dirtyland/ && sudo /opt/dirtyland/cron-dirtyland.sh --apply
```

Et on vérifie en regardant le crontab de root, qui est l'endroit où il les laisse :

```bash
sudo crontab -l
```

Ces cinq doivent y être, et **rien d'autre** de ce qui existait déjà ne doit avoir changé :

<pre>
0 6 * * * /opt/dirtyland/monitor/daily-digest.sh
0 6 * * * /opt/dirtyland/monitor/baneadas-diario.sh
*/5 * * * * /opt/dirtyland/monitor/dionaea-watch.sh
*/30 * * * * /opt/dirtyland/monitor/proxy-watch.sh
0 4 1,16 * * /opt/dirtyland/geoip/generar-tabla-paises.py --avisar >/dev/null
</pre>

On peut le lancer deux fois : si les cinq sont là, il le dit et s'en va. **Il ne fait qu'ajouter, il n'efface jamais**, car le crontab de root peut contenir des choses qui ne sont pas de ce projet, et il garde une copie du précédent. Il reconnaît chaque tâche <b>par le script, pas par la ligne entière</b>, donc si tu en changes l'heure à la main, il ne la considère pas comme absente et ne la duplique pas. Sans `--apply`, il dit seulement lesquelles manquent.

<b>`baneadas-diario.sh`</b> envoie les IP bloquées dans le pare-feu. Il part à la même heure que le résumé mais dans un message à part, et c'est voulu : le résumé dit comment va le système, ceci dit à qui on a fermé la porte, et les mélanger fait qu'aucun des deux n'est lu.

<pre>
<b>[nftables] Maquina VPS principal</b>
<b>🚫 IP's baneadas: 4</b>

<b>Automaticas</b>
  72.255.37.107  🇺🇸 Estados Unidos
  103.83.101.171  🇻🇳 Vietnam

<b>A mano, desde Telegram</b>
  43.230.94.188  🇮🇳 India

<b>De origen desconocido</b> <i>(anteriores al 29/08)</i>
  153.117.9.239  🇵🇰 Pakistan
</pre>

<b>Cela vient de la table de `nftables`, pas d'un journal à nous.</b> C'est la seule source qui dit ce que la machine bloque réellement : un fichier de notes devient obsolète dès que quelqu'un débannit à la main avec `nft delete element`.

<b>Une alerte sur une IP en cours de bannissement n'a pas de bouton.</b> Le filtre excluait déjà ce qui était banni, mais l'alerte était mise en file avant de demander le bannissement, donc au moment de dessiner le clavier l'IP n'y figurait pas encore : maintenant, on la note avant d'alerter. Et bannir une IP déjà bannie n'est pas non plus une erreur, ce qui arrive souvent car l'alerte reste dans le chat avec son bouton en dessous. On ne réécrit pas l'étiquette de celle qui y était déjà : si une IP a été bannie automatiquement puis que quelqu'un appuie sur le bouton, elle reste marquée comme automatique, car ce qui compte, c'est d'où elle est venue.

<b>Automatique ou manuel</b> vient du commentaire laissé par le bannisseur en la posant. Il y a un troisième groupe parce que, pendant un temps, les deux chemins écrivaient le même texte, si bien que pour ces bannissements-là on ne sait pas d'où ils sont venus, et les mettre dans "a mano" reviendrait à affirmer quelque chose qu'on ne sait pas. L'étiquette "a mano" a changé de texte, donc ce qui porte l'ancienne est reconnu pour ce que c'est, et ce groupe se vide tout seul à mesure qu'on débannit ou que cela expire.

Et <b>"ninguna" est aussi envoyé</b>. Un canal qui ne parle que lorsqu'il y a quelque chose ne se distingue pas d'un canal en panne : si un jour rien n'arrive, on ne sait pas s'il n'y a pas eu de bannissements ou si l'alerte a cessé de fonctionner.

<b>`dionaea-watch.sh`</b>, toutes les cinq minutes, est celui qui prévient de l'activité de Dionaea, et il est nécessaire parce que Cowrie et Dionaea ne notifient pas de la même façon : Cowrie a son plugin de sortie dans le conteneur et réagit sur le moment, alors que Dionaea n'a rien d'équivalent et qu'il faut aller lire sa base de données. Sans cette ligne, les attaques par SMB, RPC et MSSQL <b>n'arriveraient jamais sur le téléphone</b>.

<b>Cette deuxième ligne surveille aussi que Dionaea reste vivant</b>, ce qui est le blocage en boucle dont parle le début de cette section. La seule chose qui distingue "personne ne l'attaque" de "il est bloqué", c'est le moment où il a noté la dernière connexion, et ce script a déjà cette base ouverte toutes les cinq minutes. S'il s'écoule plus de <b>2 heures</b> sans une seule, il prévient par Telegram avec les deux commandes écrites dedans : `docker top dirtyland_dionaea` pour le confirmer, et `docker restart dirtyland_dionaea` pour le relancer.

<b>Et il ne répète pas la même alerte toutes les cinq minutes.</b> Ce script signale ce qui est nouveau depuis la dernière fois, et avec un attaquant insistant, c'est un robinet ouvert : un même scanner SMB laissait une ligne à chaque passe, soit 288 alertes par jour pour une seule IP. La règle est celle du plugin de Cowrie : chaque combinaison <b>IP + service + port</b> alerte ses `DIONAEA_AVISOS_POR_IP` premières fois (2) puis se tait. Se taire n'est pas oublier, car ce qui est tu est compté, apparaît résumé à la fin du message et, au bout de `DIONAEA_REAVISO_HORAS` (6), une nouvelle alerte est envoyée avec le total. <b>Ce qui n'est jamais tu, ce sont les téléchargements</b>.

<b>`generar-tabla-paises.py`</b> régénère la table des drapeaux les <b>1er et 16</b> de chaque mois. Il est dans le crontab et non dans `/etc/cron.d/dirtyland-reporter`, qui appartient au reporter et est réinstallé en entier lors de sa mise à jour. Il télécharge les fichiers publics des cinq RIR, donc il ne consomme le quota d'aucune API, et `--avisar` est ce qui le rend fiable : si un téléchargement échoue ou arrive incomplet, il ne touche pas à la table existante et le signale par le bot. Une table d'il y a un mois reste juste pour presque tout ; une demi-table, non.

Plus souvent ne servirait à rien : les RIR publient tous les jours, mais une plage change de pays très rarement. Et si un jour il faut le faire à la main (après une réinstallation, par exemple), c'est la même commande sans `--avisar` :

```bash
sudo /opt/dirtyland/geoip/generar-tabla-paises.py
```

Pour voir combien de jours a celle qui est en place, sans rien télécharger :

```
/opt/dirtyland/geoip/generar-tabla-paises.py --comprobar
```

On teste les deux manuellement sans attendre le cron :

```bash
sudo /opt/dirtyland/monitor/daily-digest.sh
```

```bash
sudo /opt/dirtyland/monitor/dionaea-watch.sh --test
```

Le `--test` signale les derniers événements <b>sans</b> marquer l'état comme lu, donc on peut le lancer autant de fois que nécessaire pour vérifier que l'envoi fonctionne sans rien perdre de la première vraie alerte.

Il prend les tokens dans le `telegram.cfg` de la section 3.4.2.7, le même bot que celui qu'utilise Cowrie, et non dans le `telegram.env` du moniteur, qui est une autre conversation. S'il répond `no pude leer bot_token/chat_id`, c'est que ce fichier n'est pas là ou qu'il lui manque les clés.

## 3.5 Signalement aux plateformes.

Un honeypot ne sert pas seulement à observer : les indicateurs qu'il capture (IP attaquantes, binaires de malware, serveurs de commande et de contrôle) ont de la valeur pour la communauté s'ils sont partagés sur les bonnes plateformes. Le signalement se fait de manière <b>automatisée mais sélective</b> : automatisée parce que les attaques arrivent à toute heure et qu'il est impossible de le faire à la main ; sélective parce qu'envoyer du bruit est le plus court chemin vers le bannissement du compte.

Le reporter est <b>un seul programme</b> qui sert les deux honeypots. La séparation ne se fait pas par honeypot mais par responsabilité :

| Dossier | Ce qu'il fait | Ce qu'il NE sait PAS |
|---|---|---|
| `collectors/` | Ils lisent Cowrie et Dionaea et traduisent leurs journaux en un modèle commun | Que les plateformes existent |
| `reporters/` | Un par plateforme. Ils appliquent leurs règles et publient | De quel honeypot vient ce qu'ils publient |
| `common/` | Modèle, état, limites de débit, transport HTTP et la barrière d'IP | - |
| `orchestrator.py` | Enchaîne tout dans le bon ordre | - |

C'est pourquoi un même module AbuseIPDB sert pour Cowrie et pour Dionaea sans une seule condition par honeypot : ce qui lui arrive est le même objet dans les deux cas.

Le vrai signalement a lieu <b>après</b> l'exposition et la capture de trafic. Cette section laisse le reporter monté et testé en simulation ; il s'allume au 3.8.

### 3.5.1 Ce qui va à chaque plateforme.

Chaque type d'indicateur a une plateforme naturelle. On n'envoie pas tout partout.

| Artefact capturé | Plateforme | Ce qui est envoyé |
|---|---|---|
| IP attaquantes | AbuseIPDB | L'IP seule, avec des catégories. Le port va dans le commentaire |
| Binaire capturé | VirusTotal | Le fichier ; et s'il passe la porte de malveillance, un commentaire signé et un vote "malicious" |
| Binaire capturé | MalwareBazaar | Le fichier, **seulement après le verdict de VirusTotal** et en passant cinq couches d'unicité |
| URL qui a servi le binaire | URLhaus | L'URL, avec `threat = malware_download` |
| Infrastructure confirmée | ThreatFox | L'IOC sous forme `ip:port` ou domaine, avec un nom de famille de Malpedia |

Les règles de sélection, le programme les applique tout seul, sans qu'il faille se souvenir de quoi que ce soit :

- <b>Avant tout</b>, ce qui n'est clairement pas un payload n'est même pas consulté. Cowrie garde comme fichier capturé tout ce que l'attaquant écrit, y compris sa clé publique quand il installe son accès. Le filtre écarte les clés SSH et le texte brut de moins de 512 octets sans en-tête exécutable ni shebang ; un ELF, un PE, une archive compressée ou un script avec `#!` poursuivent leur chemin.
- <b>AbuseIPDB</b> : seulement les sessions avec <b>handshake TCP terminé</b>, car sa politique interdit de signaler des SYN floods et du trafic UDP, dont l'origine peut être falsifiée. Dans Cowrie, cela revient à ce qu'une session existe ; dans Dionaea, à `connection_type='accept'`. Le commentaire est composé à partir de compteurs et ne contient <b>jamais</b> de texte écrit par l'attaquant, qui pourrait contenir des identifiants de tiers.
- <b>Le port publié est le 22 ou le 23</b>, pas le 2222 et le 2223 que Cowrie écrit dans son journal : l'attaquant a composé celui de l'hôte et le DNAT l'a traduit. La conversion est faite par le *collector* en construisant le modèle, avec la clé `cowrie_puertos_publicos` du `[paths]`. Dionaea n'en a pas besoin, car il publie 135, 445 et 1433 un pour un.
- <b>On nomme le service par lequel il est réellement entré</b> (`an SSH honeypot (Cowrie)`, `an SMB honeypot (Dionaea)`), jamais la liste entière des capteurs, et on ne se rabat sur le générique `an SSH/Telnet` que lorsque le journal ne le dit pas. Pour Dionaea, la donnée vient de `c.local_port` dans sa SQLite. La table vit à un seul endroit, `common/model.py`, et les deux reporters la partagent.
- <b>VirusTotal</b> : l'étiquette `#iot` n'est mise qu'avec des preuves, c'est-à-dire une architecture embarquée ou une famille de botnet IoT confirmée, car là-bas n'importe quel mot avec `#` devient une étiquette recherchable.
- <b>ThreatFox</b> : seulement des IOC validés, et seulement avec une famille traduisible en un nom <b>Malpedia</b>. Si nous ne savons pas ce que c'est, on ne l'envoie pas.
- <b>URLhaus</b> : seulement les URL dont nous avons <b>capturé le binaire</b>. Sa politique demande de ne pas envoyer d'URL hors service, mais le vérifier obligerait le honeypot à faire une requête sortante vers le serveur de l'attaquant. Avoir le fichier sur disque prouve déjà que l'URL servait le payload quand nous l'avons vue.

> [!CAUTION]
> <b>Les catégories d'AbuseIPDB sont des accusations, pas des étiquettes.</b> On ne coche que ce que les preuves soutiennent, et c'est la définition littérale de [abuseipdb.com/categories](https://www.abuseipdb.com/categories) qui fait foi, pas ce que suggère le nom.
>
> | N° | Cochée quand |
> |---|---|
> | 14 Port Scan | Trois ports distincts ou plus, ou une connexion sans rien de plus |
> | 15 Hacking | Il est entré avec des identifiants, ou a exécuté des commandes |
> | 16 SQL Injection | Dionaea a vu une tentative contre MSSQL |
> | 18 Brute-Force | Cinq tentatives de login échouées ou plus |
> | 22 SSH | Le protocole était SSH. Pas Telnet, qui est un autre protocole |
>
> Deux sont interdites : la <b>23 IoT Targeted</b>, car le leurre se présente comme un PC de bureau, et la <b>20 Exploited Host</b>, car elle affirme que la machine de l'attaquant est infectée et il n'y en a aucune preuve. `test_gates.py` échoue si quelqu'un les rajoute.

> [!CAUTION]
> <b>Nos propres IP ne sont jamais publiées</b>, ni celles des leurres ni celle du VPN d'administration. Il y a trois couches : la liste du `config.ini`, une liste fixe dans `common/ipguard.py` qui survit à un config mal modifié, et l'exclusion de toute adresse non globale. Par-dessus, il y a une barrière qui s'exécute juste avant chaque envoi et <b>lève une exception</b> au lieu de renvoyer une valeur, car une valeur de retour peut être ignorée par mégarde, une exception non.

<b>Sur ThreatFox, tu ne verras presque jamais une ligne à ton nom, et ce n'est pas un défaut.</b> Si l'IOC existe déjà, ThreatFox le fusionne avec l'existant et ne met à jour que son `last_seen`, donc le `reporter` de l'indicateur reste celui qui l'a soumis en premier. Le résumé le détaille pour qu'on ne croie pas que les envois se sont perdus.

```bash
sudo python3 -c "
import configparser, requests
cp = configparser.ConfigParser(inline_comment_prefixes=('#',';'))
cp.read('/opt/dirtyland/platform-reporter/config.ini', encoding='utf-8')
r = requests.post('https://threatfox-api.abuse.ch/api/v1/',
                  json={'query':'search_ioc','search_term':'IOC-A-BUSCAR'},
                  headers={'Auth-Key':cp.get('api_keys','abusech').strip()}, timeout=30)
print(r.text[:900])"
```

Si le `last_seen` correspond à l'heure de ton envoi, il est arrivé. La clé est lue dans le `config.ini` et n'est pas affichée.

### 3.5.2 La règle d'or : VirusTotal d'abord.

Cette section existe parce que **cela nous a coûté un bannissement**.

MalwareBazaar n'accepte que du malware **confirmé et de moins de 10 jours**. L'erreur a été de filtrer par la date du fichier sur disque, qui ne dit pas l'âge du malware : elle dit **quand nous l'avons capturé**. Un binaire vieux de plusieurs mois téléchargé aujourd'hui passait le filtre sans problème, et un échantillon de ce genre a suffi pour qu'abuse.ch ferme le compte.

La correction : l'ancienneté vient du <b>`first_submission_date` de VirusTotal</b>, et s'il n'y a pas de verdict, on ne soumet pas. La date du fichier n'est utilisée pour rien.

Et il y a une deuxième raison, celle-ci de paternité : il existe des bots qui surveillent les publications de MalwareBazaar et se précipitent pour soumettre le même échantillon à VirusTotal afin d'apparaître eux-mêmes comme découvreurs. Publier d'abord sur MalwareBazaar, c'est les prévenir. C'est pourquoi l'ordre est strict et le programme n'en permet pas d'autre :

1. <b>Soumettre à VirusTotal dès la capture.</b> Avec cela, la paternité est déjà à nous. Rien de plus : ni commentaire, ni vote.
2. <b>Attendre.</b> Les moteurs ont besoin d'heures pour se mettre à jour.
3. <b>Regarder le verdict</b> et décider.
4. S'il passe la porte : <b>commentaire signé et vote "malicious"</b> sur VirusTotal.
5. <b>Et seulement alors</b>, MalwareBazaar, URLhaus et ThreatFox.

Séparer l'étape 1 de l'étape 3, c'est ce qui résout la tension entre "seulement du malware confirmé" et "échantillon frais" : la soumission est immédiate, le jugement attend. On regarde de nouveau toutes les 12 heures et on abandonne au bout de 8 jours, avec une marge largement suffisante dans la fenêtre de 10.

<b>La porte de malveillance : 12 + 3.</b> Ce sont <b>deux questions différentes</b> :

| # | Condition | Qui bloque-t-elle ? |
|---|---|---|
| 1 | L'analyse de VirusTotal est terminée | tous |
| 2 | **>= 12 moteurs** en `malicious` | tous |
| 3 | Aucun signal dominant d'adware ou de PUP | tous |
| 4 | **>= 3 moteurs concordant sur la même famille** (`mirai`, `gafgyt`, `redtail`...), pas des génériques du type `Trojan.Generic` | seulement MalwareBazaar et ThreatFox |

Les trois premières répondent à **"est-ce du malware ?"**. La quatrième répond à **"savons-nous comment il s'appelle ?"**, qui est autre chose, et seules l'exigent les deux plateformes qui publient l'échantillon étiqueté avec un nom de famille. VirusTotal, URLhaus et le signalement du serveur qui a servi le binaire n'en ont pas besoin.

Douze moteurs disant `Trojan.Generic`, ce sont douze heuristiques qui peuvent venir du même classificateur ; trois disant `Mirai` signifient que quelqu'un a reconnu la famille. C'est pourquoi le seuil de détections ne suffit pas à lui seul.

<b>Comment on décide du nom de famille.</b> Le filtre est une liste noire de ce qui n'est pas un nom (`trojan`, `generic`, `linux`, `elf`, `agent`, `heur`, `malware`...), et dans ce qui reste, on prend le plus fréquent. Cela laisse un trou qu'il faut boucher à part : presque tous les moteurs collent un suffixe de variante au nom (`ELF:Mirai-ABC`), et ce suffixe met à égalité des variantes de la même famille, donc on retire ces suffixes avant de compter.

Si cela échoue, ce n'est pas grave : sur MalwareBazaar, la famille est une étiquette, pas une signature, et ThreatFox exige en plus un équivalent confirmé dans Malpedia.

<b>Un refus qui ne s'améliore pas en attendant n'est plus réessayé.</b> Le verdict et le nombre de détections, eux, s'améliorent, car les moteurs se mettent à jour, donc ces échantillons retournent dans la file. L'ancienneté ne s'améliore jamais : un hash qui est dans VirusTotal depuis 215 jours y sera depuis 216 demain, et le réessayer, c'est dépenser du quota pour recevoir le même non.

Ni VirusTotal ni MalwareBazaar ne publient de seuil numérique officiel. Le 12 + 3 est <b>un critère à nous</b> et c'est indiqué ainsi dans le `config.ini`.

Ce que compte le deuxième nombre, ce sont des <b>concordances, pas des noms distincts</b>. En comptant les noms, le critère était à l'envers : un WannaCry que les vingt moteurs nomment de la même façon comptait pour un, et un échantillon confus avec quatre noms répartis comptait pour quatre.

### 3.5.3 Les deux vetos de politique et les cinq couches d'unicité de MalwareBazaar.

<b>Avant les cinq couches, il y a une porte qui protège le compte, et ce sont deux vetos d'origine différente.</b>

**1. Infecteurs de fichiers.** C'est le seul veto **écrit** : la FAQ de MalwareBazaar demande de ne pas soumettre de "file infectors and/or worms".

**2. WannaCry.** **Il n'apparaît pas dans la FAQ.** Il vient d'une question posée par e-mail à Roman Hüssy, fondateur d'abuse.ch, qui a répondu littéralement : *"You can skip WannaCry, rest is fine"*.

Les deux listes vivent dans le `config.ini` et non dans le code, et c'est une troisième réponse à la même question qui en décide :

> "No, there is no list of disallowed malware families. If we encounter any issues with your submissions we would for sure contact you."

Il n'y a pas de catalogue public d'exclusions et l'avertissement est <b>réactif, par e-mail</b>, donc la liste doit pouvoir être étendue sans toucher à un fichier de programme : on ajoute le terme et on recrée le conteneur. La contrepartie est qu'un effacement accidentel les désactive sans que rien n'échoue, et c'est pourquoi le `--self-test` prévient si l'une d'elles est vide.

> [!WARNING]
> <b>Ce qui N'est PAS filtré, et qu'il vaut mieux ne pas "corriger" plus tard.</b> La même question a précisé que la règle vise les infecteurs classiques et non n'importe quelle famille auto-propagatrice : <b>Mirai est acceptable</b>. C'est pourquoi on ne filtre pas sur le mot "worm" ni sur la catégorie que déclare un moteur, car certains antivirus étiquettent Mirai comme `Worm.Linux.Mirai` et ce filtre jetterait justement ce que capture le leurre telnet. Un test échoue si quelqu'un essaie.

<b>Comment il compare.</b> En minuscules et par correspondance partielle, contre les étiquettes brutes des moteurs et contre notre classification de famille. Partielle, parce que la même bestiole est étiquetée de dix façons (`Ransom.WannaCry.A`, `Trojan.WannaCrypt`, `W32/WCry.gen`) et qu'exiger l'exactitude en laisserait passer neuf. Et <b>fail-closed</b> : si la classification ne peut pas être déterminée, on ne soumet pas. Cette porte de veto passe la première de toutes, pour qu'un échantillon frappé de veto ne consomme ni quota ni appel réseau.

Cette liste n'est pas celle qui écarte le WannaCry de toujours : c'est déjà la porte de fraîcheur qui s'en charge, car les hashes canoniques sont dans VirusTotal depuis des années et tombent d'eux-mêmes. Cette liste agit sur les variantes réempaquetées avec un nouveau hash, qui sont les seules qui arriveraient jusqu'ici.

Dans le `--show-rejections` et dans le journal, ces refus apparaissent comme `politica-wannacry`, `politica-infector-de-fichero` ou `politica-sin-clasificar`, et chaque ligne dit **quel terme a correspondu et dans quelle source**, pour pouvoir l'auditer :

<pre>
rechazado [malwarebazaar/politica-wannacry] 300a5c00a00549d9: coincide 'wannacry' en etiqueta VirusTotal 'ransom.wannacry.a'
</pre>

Portée : <b>seulement MalwareBazaar</b>. À VirusTotal, on continue de tout soumettre, car là-bas rien n'est de trop, et à AbuseIPDB on continue de signaler l'IP, car celui qui distribue un WannaCry est réellement une machine compromise.

En outre, sa politique interdit le *hash busting* (soumettre le même malware avec un remplissage modifié pour gonfler le compteur) et demande un échantillon par campagne. Cinq contrôles, du moins coûteux au plus coûteux :

| Couche | Contrôle |
|---|---|
| 1 | Nous avons déjà soumis ce hash -> état local |
| 2 | Le hash est déjà dans MalwareBazaar -> `get_info`, et **fail-closed** : si la requête échoue, on suppose qu'il existe et on ne soumet pas |
| 3 | Même clan de similarité (`vhash` / `ssdeep` de VirusTotal) que quelque chose de déjà soumis |
| 4 | Même triplet **(famille, hôte de téléchargement, architecture de l'ELF)** sur 30 jours |
| 5 | Rafale : plusieurs binaires de même origine, de même architecture et de taille presque identique en peu de temps |

La couche 4 est celle qui distingue le légitime du piège : un binaire `mips` et un `arm` de la même campagne sont des fichiers <b>réellement différents</b> et les deux sont soumis ; deux du même `arm` qui ne diffèrent que par le remplissage, non.

La couche 5 <b>ne s'applique pas quand il n'y a pas de campagne connue</b>. Elle cherchait des rafales "de même origine", et si l'origine est inconnue, compter ensemble les échantillons non classés revient à inventer une campagne : trois binaires différents de trois attaquants différents se bloquaient entre eux.

<b>Ce que mesure l'ancienneté, car il est facile de le comprendre à l'envers.</b> Elle ne mesure pas l'âge de la famille, elle mesure depuis combien de temps cet artefact est connu : un WannaCry dont le hash est dans VirusTotal depuis 215 jours est du matériel rance et un dont personne n'a vu le hash est une variante qui circule maintenant, même si la famille date de 2017. C'est pourquoi, quand nous sommes les premiers à soumettre, l'âge vaut zéro : l'échantillon est aussi neuf qu'il peut l'être.

Et par-dessus tout, un <b>plafond strict</b> : 5 soumissions par jour et 20 par semaine. Même si toute la logique précédente échouait, il est impossible d'inonder la plateforme.

<b>Le goutte-à-goutte : `max_per_run`.</b> Tout ce qui précède décide de <b>ce qui</b> peut être publié. Il reste à décider <b>combien à la fois</b>, ce qui est une autre question et échappe aux portes de qualité : si une nuit cinquante binaires arrivent qui passent tous les filtres, les cinquante sont publiables et pourtant les soumettre d'affilée ne se distingue pas d'un déversement automatique. Et les plateformes pénalisent ce comportement même si chaque échantillon est bon.

C'est pourquoi chaque plateforme a un plafond par passe, et ils sont délibérément bas :

| Plateforme | Par passe | Pourquoi |
|---|---|---|
| VirusTotal | 6 | Chaque échantillon consomme jusqu'à trois (soumission, commentaire, vote) : cela fait deux échantillons complets |
| MalwareBazaar | 6 | Chaque échantillon en consomme deux (soumission et commentaire) : cela fait trois échantillons. Celle qui a déjà coûté un bannissement ; avec le plafond de 5 par jour, cela évite qu'ils partent d'affilée |
| ThreatFox | 3 | Même compte que MalwareBazaar et URLhaus : un bannissement éteint les trois |
| URLhaus | 3 | Même compte, et son format n'a jamais été testé contre la vraie API |
| AbuseIPDB | 25 | Voir ci-dessous |

<b>Ce qui arrive à ce qui ne part pas.</b> Cela ne se perd pas, mais les échantillons et les IP sont réessayés par des chemins différents, et cette nuance fixe les chiffres du tableau. Les <b>échantillons</b> vivent dans une file persistante, la table `samples` : si l'un n'est pas parti à cause d'un plafond, il est reprogrammé une heure plus tard et abandonné au bout de 8 jours. Les <b>IP et les URL</b> n'ont pas de file propre, elles sont de nouveau déduites des journaux à chaque passe, donc elles sont réessayées toutes seules, mais seulement tant qu'elles restent dans `lookback_hours` : passées ces 24 heures, une IP qui n'a jamais trouvé de place disparaît sans avoir été signalée, et c'est pourquoi le plafond d'AbuseIPDB doit être au-dessus du rythme auquel arrivent les attaquants.

Dans le journal, ce qui est reporté apparaît comme un refus `tope-por-pasada` indiquant qu'il sera réessayé. Un échantillon n'est considéré comme terminé que si tout est vraiment parti : les reporters distinguent le report dû à un plafond de débit du refus de fond, comme l'ancienneté, qu'il n'y a pas de sens à réessayer.

<b>Et ce qui arrive à ce qui a bien été signalé : `retention_days`.</b> C'est enregistré, et il le faut, car c'est la mémoire qui empêche de soumettre de nouveau un échantillon déjà soumis. Mais tout ce qui est conservé ne sert pas à décider quelque chose et, sans nettoyage, la base grossit sans limite : la même IP en période de refroidissement laisse une ligne toutes les quinze minutes disant la même chose.

À la fin de chaque passe, on fait une purge avec deux règles :

| Conservé pour toujours | Jeté au bout de `retention_days` (30) |
|---|---|
| Les soumissions identifiées par **hash** (VirusTotal, MalwareBazaar) | L'historique des **refus**, qui n'est que de l'audit |
| La table `samples`, limitée et qui est en plus la file de revérification | Les signalements à AbuseIPDB, dont la clé est `ip@fecha` et dont la fenêtre est de 24 h |
| | Les compteurs de quota par jour, dont seuls les sept derniers sont nécessaires |

La première colonne est intouchable : effacer une ligne de soumission par hash, c'est commencer à faire des doublons sur les plateformes, ce qui a coûté le bannissement, et cela occupe très peu. Un `retention_days = 0` désactive toute la purge : sans cette garde, la coupure deviendrait <i>maintenant</i> et emporterait même les signalements du jour.

Il y a deux index, sur `rejections(ts)` et sur `sent(platform, sent_at)`. Sans le premier, la requête du disjoncteur parcourait entièrement la table qui grossit le plus. SQLite ne rend pas l'espace en effaçant, donc on compacte avec `VACUUM` seulement quand la purge retire plus de 20 000 lignes.

C'est par passe et non par jour, exprès. Un plafond quotidien laisse partir toute la rafale d'un coup puis se tait, ce qui est exactement le comportement qu'on veut éviter ; celui-ci répartit toujours.

AbuseIPDB est plus haut parce que c'est la seule dont la politique prévoit de recevoir des signalements de honeypots en volume, et parce qu'on ne collecte que les dernières `lookback_hours` : un plafond en dessous du rythme d'arrivée des attaquants laisserait la file non vidée et les plus anciens sortiraient de la fenêtre sans être signalés.

| | |
|---|---|
| Limite du compte gratuit | 1000 par jour, signalements <b>et</b> consultations additionnés, remise à zéro à 00:00 UTC |
| Même IP | une fois toutes les 15 minutes, de son côté |
| Ce que consomme le reporter | un appel par IP et par jour : il n'utilise que `/report`, jamais `/check` |
| Plafond de notre configuration | 25 par passe x 96 passes = 2400 par jour |
| Ce qui est réellement envoyé | autant qu'il y a d'IP distinctes, car `min_hours_between_reports = 24` en laisse une par IP et par jour |

La vraie limite est fixée par le signalement unique par IP et par jour, pas par `max_per_run` : avec une centaine d'IP distinctes par jour, on consomme 10 % du quota. Il ne faudrait s'en préoccuper qu'au-delà de 1000 par jour, et alors un compte webmaster suffit, gratuit et nécessitant seulement de vérifier un domaine, qui porte la limite à 3000.

### 3.5.4 Installer le reporter depuis le dépôt.

Il est dans le dossier **REPORTING PLATFORM SCRIPTS** du dépôt. Il a besoin de `python3-requests` :

```bash
sudo apt install -y python3-requests
```

Il est déjà sur le VPS avec le reste du dépôt, donc on le place dans l'arborescence créée à la section 3.4. D'abord, on vide la destination, en conservant le `config.ini` s'il existait déjà (ainsi, la même commande sert à installer et à mettre à jour, sans laisser de vieux fichiers qui traînent) :

```bash
sudo find /opt/dirtyland/platform-reporter -mindepth 1 -maxdepth 1 ! -name config.ini -exec rm -rf {} + && sudo cp -a "/tmp/dirtyland-repo/REPORTING PLATFORM SCRIPTS/." /opt/dirtyland/platform-reporter/ && sudo chown -R root:root /opt/dirtyland/platform-reporter && sudo find /opt/dirtyland/platform-reporter -type f -name '*.py' -exec chmod 640 {} + && sudo chmod 750 /opt/dirtyland/platform-reporter/orchestrator.py /opt/dirtyland/platform-reporter/malware-watch.sh && echo "reporter instalado"
```

Elle doit se terminer en affichant `reporter instalado`.

Les répertoires d'état et de journalisation :

```bash
sudo install -d -m 750 -o root -g root /var/lib/dirtyland-reporter /var/log/dirtyland-reporter
```

### 3.5.5 Configuration et liste de blocage.

Le `config.ini.example` ne contient aucune clé : les marqueurs `<ASÍ>` se remplissent dans la copie de `/opt`, jamais dans le dépôt.

> [!IMPORTANT]
> Ici, on remplit <b>uniquement la liste de blocage</b>. Les clés d'API <b>NE se mettent PAS encore</b> : elles viennent tout à la fin, à la section <b>3.8.1</b>, juste avant d'exposer le leurre. Tant que le honeypot reste scellé, il n'y a rien à signaler, donc cela n'a aucun sens d'avoir les clés en place.

```bash
sudo install -m 600 -o root -g root /opt/dirtyland/platform-reporter/config.ini.example /opt/dirtyland/platform-reporter/config.ini
```

```bash
sudo nano /opt/dirtyland/platform-reporter/config.ini
```

Ici, on remplit <b>cinq choses</b> :

| Clé | Section | Obligatoire |
|---|---|---|
| `ips` | `[blocklist]` | **Oui.** Le programme refuse de démarrer avec une liste vide. **IMPORTANT** : mettre les IP des proxys et du serveur VPN lui-même que tu utilises, c'est-à-dire 3 proxys + 1 serveur |
| `cowrie_log_tz` | `[paths]` | Oui, si le conteneur de Cowrie n'est pas en UTC |
| `attribution_tag` | `[general]` | Non. Sans elle, ce qui est publié n'est pas signé |
| `usuario` | `[threatfox]` | Non. Sans elle, le résumé ne distingue pas un nouvel IOC d'un rafraîchissement |
| Les six liens | `[perfiles]` | Non. Sans eux, le résumé quotidien ne montre pas tes profils |

Elles sont loin les unes des autres, avec de longs blocs de commentaires au milieu, donc ne les cherche pas à l'œil. Ceci dit à quelle ligne se trouve chacune, et de `[perfiles]` montre toute la section :

```bash
sudo awk '/^\[/ {sec=$0} sec=="[perfiles]" || /^(ips|cowrie_log_tz|attribution_tag|usuario)[ \t]*=/ {if ($0 !~ /^[ \t]*(;|#|$)/) printf "%4d  %s\n", NR, $0}' /opt/dirtyland/platform-reporter/config.ini
```

Et ceci, une fois l'édition terminée, liste **tout marqueur qui n'a pas encore été remplacé** :

```bash
sudo grep -nE '^[^;]*<[^>]+>' /opt/dirtyland/platform-reporter/config.ini
```

Les trois `api_key` du début apparaissent exprès, car elles se remplissent au 3.8.1, et l'`usuario` de `[threatfox]` peut garder son marqueur si tu préfères ne pas le mettre.

En commençant par la liste : remplacer `<IPS-DE-ADMINISTRACION>` par <b>tous</b> les nœuds de sortie du VPN depuis lesquels tu administres (les mêmes qui apparaissent dans la règle `nftables` qui ouvre le port SSH). Les deux IP publiques du VPS sont déjà en place. Les `api_key` restent telles quelles, avec leur marqueur.

Il y en a plusieurs et il faut toutes les mettre. À la section 3.8.2, nous nous connectons au leurre <b>depuis l'extérieur</b> pour vérifier qu'il est bien exposé, et cette connexion sort par le nœud du VPN : s'il n'est pas dans la liste, la vérification finit par nous signaler nous-mêmes.

> [!TIP]
> Si tu changes de nœud de sortie, ajoute-le <b>avant</b> de l'utiliser : une entrée en trop ne fait pas de mal, une entrée manquante, si. La contrepartie est qu'un vrai attaquant entrant depuis l'un de ces nœuds ne sera pas signalé, et il ne reste pas caché : il apparaît dans `--show-rejections` avec le motif `en la lista de bloqueo (infraestructura propia)`. Le programme refuse de démarrer si le fichier est lisible par quelqu'un d'autre que son propriétaire, ou si `[blocklist]` est vide.

Les deux IP du VPS sont en plus écrites dans `common/ipguard.py`, dans `HARDCODED_NEVER_REPORT`, et c'est redondant exprès : si quelqu'un perd le `config.ini` lors d'une réinstallation, ces deux-là restent protégées. Cette liste est <b>la seule</b> qui dit "ceci, c'est nous", et trois choses la lisent : le reporter pour ne pas nous signaler, `ssh-watch.sh` pour marquer nos propres accès au lieu de donner l'alarme, et `dionaea-watch.sh` pour ne pas alerter sur nos vérifications. Ajouter ici un nouveau nœud règle le problème pour les trois.

Pour les tests du quotidien, il y a une façon de ne pas dépendre de cette liste : <b>entrer dans le leurre depuis l'intérieur du VPS lui-même</b>, avec `ssh -p 2222 alyosha@172.20.0.10`, qui atteint le conteneur sans passer par Internet et avec une origine déjà privée.

<b>Ce qui est publié est en anglais, et c'est de l'OPSEC.</b> Les commentaires de VirusTotal et d'AbuseIPDB sont des textes publics et permanents sur des plateformes internationales : l'espagnol restreindrait le cercle des personnes qui pourraient être derrière, et l'anglais est en plus ce qu'on attend là-bas.

<b>La signature : `attribution_tag`.</b> Elle est ajoutée à la fin des commentaires de VirusTotal, qui est l'endroit où il est logique de revendiquer la paternité d'un échantillon soumis pour la première fois. Elle va dans `[general]` et, comme les nœuds du VPN, elle s'écrit sur la machine et non dans le dépôt. La laisser vide ne signe rien, et un marqueur non remplacé n'est pas publié non plus ; le `--self-test` prévient si on l'oublie.

Sur MalwareBazaar, l'attribution n'est pas un champ de la soumission : la plateforme la reçoit dans un autre appel, avec `query=add_comment`, juste après que la soumission a réussi. Le texte est du genre :

<pre>First-seen sample captured in-the-wild by an SMB honeypot (Dionaea) on 2026-08-19 (UTC). First submission by &lt;TU-HANDLE&gt;.</pre>

Ce commentaire est un envoi de plus, et c'est pourquoi le plafond par passe de MalwareBazaar est de 6 : cela fait <b>trois échantillons</b>, chacun avec sa soumission et son commentaire. Il doit être pair, car avec un nombre impair, la dernière soumission de la passe se retrouve sans commentaire, et ce commentaire n'est jamais réessayé. Les plafonds de 5 par jour et 20 par semaine ne comptent que les clés `upload:` ; en comptant tous les envois, le commentaire mangerait la moitié du quota.

Il y a un deuxième interrupteur, `anonymous` : les trois plateformes d'abuse.ch l'acceptent à chaque envoi, avec `1` pour publier sans nom et `0` pour attribuer à ton compte, et les trois reporters envoient `0`. Ce n'est pas la même chose qu'`attribution_tag` : `anonymous` décide si la plateforme te reconnaît comme expéditeur, et `attribution_tag` écrit le handle <b>dans le texte</b>, ce qui est la seule chose qui survit quand un tracker republie l'échantillon ailleurs.

> [!WARNING]
> Ce handle <b>NE doit JAMAIS apparaître dans le honeyfs</b>. Là, il serait le fil qui relie le leurre à la personne qui l'opère, et l'attaquant est à l'intérieur de la machine, pas en train de lire VirusTotal. Il fait partie de la liste des chaînes à chercher avec grep quand on audite le système de fichiers factice.

<b>L'heure des événements : `cowrie_log_tz`.</b> Elle doit avoir la même valeur que le fuseau horaire <b>du conteneur</b> de Cowrie (ici `Europe/Kyiv`, en raison de l'identité du leurre), pas celui de l'hôte. Si le conteneur est en UTC, on laisse `UTC` et il n'y a rien à faire.

C'est nécessaire parce que Cowrie signe ses horodatages avec un `Z`, qui signifie UTC, mais écrit l'heure <b>locale</b>. Avec le leurre à Kyiv, cela fait trois heures de trop, et l'erreur ne se montre nulle part car la chaîne est un ISO valide : la seule chose qui se passe, c'est qu'AbuseIPDB reçoit des signalements datés <b>dans le futur</b>, qui, en plus d'être rejetables, sont de fausses données dans une base utilisée par beaucoup de monde. Dionaea n'a pas ce problème, car il stocke l'epoch dans sa SQLite.

On ne peut pas le corriger à la source, car le JSON de Cowrie n'inclut pas l'epoch et mettre `TZ=UTC` dans le conteneur ferait que le `date` à l'intérieur du leurre ne serait plus à l'heure de Kyiv. On le corrige à la lecture : un horodatage avec un décalage explicite est respecté, et seuls le `Z` et les horodatages sans fuseau sont réinterprétés. Pour confirmer dans quel fuseau est le conteneur :

```bash
sudo docker exec dirtyland_cowrie /cowrie/cowrie-env/bin/python3 -c "import time; print(time.tzname)"
```

Le collecteur ne prévient que si quelque chose reste faux : s'il détecte des événements datés après l'heure actuelle, il écrit dans le journal <code>N eventos con fecha en el FUTURO: revisa cowrie_log_tz</code>. Avant, ce décalage était totalement silencieux, ce qui l'a rendu difficile à trouver.

<b>Le `--self-test` vérifie cette clé.</b> Il prend la dernière ligne du `cowrie.json` et la compare à la date de modification du fichier, que le système met à jour en temps réel : cette ligne a été écrite à cet instant, donc si en la convertissant avec le fuseau configuré on n'obtient pas cette heure, le fuseau est faux, et l'avertissement dit de combien d'heures est le décalage. Il compare le journal avec lui-même et non avec l'heure de l'hôte. C'est pourquoi déménager la machine dans un autre pays ne change rien : la clé dit dans quel fuseau écrit le conteneur, pas où se trouve le serveur.

<b>Ton nom sur ThreatFox : `usuario`.</b> Il va dans `[threatfox]`, et ce n'est pas le lien de `[perfiles]` : celui-là contient un identifiant, et ceci est le nom que ThreatFox affiche dans "You are viewing the user profile of...". Copie-le tel quel.

Il sert à une vérification après publication : `submit_ioc` répond `query_status=ok` que ThreatFox crée l'indicateur ou le fusionne avec celui d'une autre personne, et son API ne documente pas la différence, donc après chaque publication on demande avec `search_ioc` qui figure comme `reporter`. Le résultat est enregistré avec l'envoi et le résumé le détaille :

<pre>
• 🟢 threatfox:      3 publicadas (1 nuevo, 1 ya era de otro, 1 sin verificar)
</pre>

Cela coûte une requête par publication. Si tu le laisses avec son marqueur, ce n'est pas grave : on publie quand même et le détail indique "sin verificar".

<b>Les liens vers tes profils : `[perfiles]`.</b> Il y en a six, et ce n'est pas le publicateur qui les utilise, c'est le résumé quotidien. Quatre sont le compte de chaque plateforme ; les deux autres sont d'abuse.ch et ne mènent pas au même endroit : `URLhaus` est la vue de ce service et `abuse.ch` est le profil général de la communauté, qui est l'endroit où l'on voit la réputation qui gouverne les quatre à la fois.

Ils vont sur la machine et non dans le dépôt, pour la même raison qu'`attribution_tag`. Remplace `TU-ID` par le tien dans chacun (ou efface la ligne que tu ne veux pas) :

<pre>
[perfiles]
MalwareBazaar = &lt;https://bazaar.abuse.ch/user/TU-ID/&gt;
ThreatFox     = &lt;https://threatfox.abuse.ch/user/TU-ID/&gt;
URLhaus       = &lt;https://urlhaus.abuse.ch/user/TU-ID/&gt;
abuse.ch      = &lt;https://community.abuse.ch/u/TU-USUARIO&gt;
AbuseIPDB     = &lt;https://www.abuseipdb.com/user/TU-ID&gt;
VirusTotal    = &lt;https://www.virustotal.com/gui/user/TU-HANDLE&gt;
</pre>

Le nom à gauche est <b>le texte du lien</b>, donc laisse-le lisible. Et il n'y a aucun moyen de faire une bêtise : un lien vide, ou un lien avec le marqueur `<ASÍ>` non remplacé, n'est tout simplement pas affiché (le script ignore toute valeur qui commence par `<`). Si tu n'en remplis aucun, la section "Mis perfiles" du résumé n'apparaît pas, et c'est tout.

### 3.5.6 Vérification préalable.

Toutes les commandes du reporter portent `sudo` car le `config.ini` est en `600` et appartient à `root` : sans lui, le reporter ne peut pas lire ses propres clés et échoue sur les permissions.

Avant tout, que le programme se vérifie lui-même :

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --self-test
```

Il vérifie la configuration, les permissions, que l'état peut être écrit et <b>exécute la barrière d'IP contre des cas connus</b>, en vérifiant que les nôtres sont rejetées et qu'une IP étrangère passe.

À ce stade, il va sortir avec le code 3, et c'est correct : il se plaindra des `api_key`, car ce sont encore les marqueurs du dépôt. On les met au 3.8.1, juste avant d'exposer.

Tant que les clés ne sont pas mises, aucune plateforme n'est utilisée : elles sont entièrement sautées et le journal en garde la trace. On ne fait même pas les requêtes de lecture.

### 3.5.7 Essai à blanc.

<b>Par défaut, il ne publie rien.</b> Il faut `--live` explicitement, et cette décision est prise dans le transport HTTP, au seul endroit qui ouvre un socket, et non répartie dans chaque reporter : ainsi, aucun chemin ne peut s'échapper par un oubli.

Simulation ne veut pas dire qu'on ne touche pas au réseau. Les <b>publications</b> (soumettre un fichier, commenter, voter, signaler une IP) ne partent pas. Les <b>requêtes</b> de lecture, si : le verdict de VirusTotal, qui est ce qui décide si quelque chose est du malware, est réellement demandé et consomme du quota.

Tant que les `api_key` restent les marqueurs de l'exemple, on ne fait même pas cela : la plateforme compte comme non configurée et elle est entièrement sautée, avec une trace dans le journal. Ainsi, le cron ne passe pas son temps à accumuler des réponses `401` depuis notre IP pendant les jours qui séparent l'installation de la mise en place des clés.

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini
```

Dans le journal apparaît chaque requête qui <b>aurait</b> été envoyée, avec son URL et son corps (les clés apparaissent comme `[REDACTED]`). Et le plus utile, pourquoi le reste N'a PAS été envoyé :

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --show-rejections 30
```

<pre>
abuseipdb    handshake     45.9.148.99   sin handshake TCP confirmado: la politica prohibe...
malwarebazaar antiguedad   7794cb2e...   vista por primera vez hace 30 dias, el maximo son 10
threatfox    familia       1.2.3.4       familia 'cosarara' sin equivalente confirmado en Malpedia
</pre>

Chaque refus est enregistré avec son motif, donc "pourquoi ceci n'a pas été signalé" a toujours une réponse.

<b>Et le résumé de chaque passe distingue qui ne l'a pas envoyé</b>, ce qui est une question différente de combien :

<pre>
abuseipdb: 3 enviados, 280 ya cubiertas, 3 descartadas
</pre>

| Groupe | Ce que cela signifie |
|---|---|
| **ya cubiertas** | Rien à faire : nous l'avons envoyé avant, la plateforme l'a déjà, ou cela tombe dans une fenêtre de refroidissement |
| **descartadas** | Ne remplit pas nos critères : sans handshake, sans verdict, adware, trop ancien... |
| **aplazadas** | Sera envoyé : plafond de la passe, plafond quotidien, quota épuisé |
| **RECHAZADAS POR LA PLATAFORMA** | Le seul qui soit un refus venant d'ailleurs. S'il n'est pas à zéro, il y a quelque chose à regarder **aujourd'hui** |

Avant, c'était un seul nombre pour vingt motifs, et lire `283 rechazados` pour AbuseIPDB inquiétait sans raison : c'étaient 280 IP déjà couvertes par la fenêtre de 24 heures, c'est-à-dire le système fonctionnant exactement comme il le doit. On ne nomme que les groupes qui contiennent quelque chose ; une ligne avec quatre zéros se lit moins bien et ne dit rien.

Les codes de sortie sont différents exprès, pour que le cron puisse les distinguer :

| Code | Signification |
|---|---|
| 0 | Tout va bien |
| 1 | Erreur inattendue |
| 2 | Problème de configuration |
| 3 | Le self-test a échoué |
| 4 | Terminé avec des erreurs réseau ou des refus de plateforme |
| 5 | Quota épuisé (ce n'est pas un échec : c'est le système qui fonctionne) |

### 3.5.8 Automatisation.

Le fichier cron <b>est déjà écrit dans le dépôt</b> : il n'y a pas à le taper, seulement à le copier à sa place.

```bash
MODO=$(grep -qE '^[[:space:]]*\*/15 .*malware-watch\.sh --live' /etc/cron.d/dirtyland-reporter 2>/dev/null && echo live || echo sim) && sudo install -m 644 -o root -g root /opt/dirtyland/platform-reporter/cron.d/dirtyland-reporter /etc/cron.d/dirtyland-reporter && { [ "$MODO" = live ] && sudo sed -i -E 's|^(\*/15 .*malware-watch\.sh)$|#\1|; s|^#(\*/15 .*malware-watch\.sh --live)$|\1|' /etc/cron.d/dirtyland-reporter; true; } && grep -vE '^\s*(#|$)' /etc/cron.d/dirtyland-reporter | grep malware-watch
```

La commande affiche la ligne qui est restée active : c'est cette sortie qu'il faut regarder. Sur une installation depuis zéro, ce sera celle de simulation, ce qui est correct.

La commande regarde d'abord dans quel mode on était, car le modèle du dépôt a la ligne <b>sans</b> `--live` activée, donc un simple `install` remettrait la machine en simulation sans rien dire. C'est pourquoi on lit le fichier installé et on conserve le mode.

Lors de la <b>mise à jour</b> du reporter, il n'est toujours pas nécessaire de l'exécuter : le `cp -a` du 3.5.4 copie dans `/opt/dirtyland/platform-reporter/`, et là il ne touche que le modèle source, que cron ne lit même pas.

Et il n'est plus nécessaire de penser à le regarder. Le résumé quotidien de Telegram indique le mode, et les points de couleur des plateformes en dépendent : avec le cron en simulation, les cinq sortent en rouge, et en dessous il y a une ligne qui dit pourquoi.

```
• 🔴 abuseipdb:      0 publicadas, 14 SIMULADAS (no se publicaron), 394 ya cubiertas
[MOTIVO: crontab esta usando modo simulacion]
```

En simulation, les publications sont à zéro et les simulées apparaissent à part, désignées par leur nom : une simulation laisse une trace dans la base comme un vrai envoi, pour pouvoir montrer comment se comporterait la déduplication, mais elle n'a rien publié. Une plateforme activée avec le cron en simulation ne dit plus `REPORTING` mais `on, but muted by cron`.

<b>Ces chiffres portent vraiment sur 24 heures.</b> Ils viennent de la base d'état, la même table que le reporter consulte pour ne pas répéter un envoi, et non d'une reconstruction en lisant le `reporter.log`, dont les résumés ne portent que sur une passe de quinze minutes. Les groupes de motifs sont ceux de `reporters/base.py`, et un test compare les deux répartitions pour qu'elles ne puissent pas diverger en silence.

La télémétrie lit aussi les journaux en rotation, car `reporter.log` est découpé plusieurs fois par jour. Et "errores" ne compte plus ce qui n'est pas une erreur : une coupure réseau ou un 5xx au milieu d'une publication est une condition prévue, donc c'est un `WARNING`, et l'`ERROR` est réservé à ce qui demande une action. Les orphelins d'AbuseIPDB, les envois dont le résultat n'a pas été confirmé, sont normaux : le signalement est presque toujours arrivé, et sinon cette IP sera signalée demain avec une nouvelle clé.

Il vaut mieux vérifier qu'il est arrivé, car `install` ne dit rien quand il fonctionne :

```bash
cat /etc/cron.d/dirtyland-reporter
```

En retirant les commentaires, voici ce qui doit s'y trouver :

<pre>
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

*/15 * * * * root /opt/dirtyland/platform-reporter/malware-watch.sh
#*/15 * * * * root /opt/dirtyland/platform-reporter/malware-watch.sh --live

17 6 * * * root /usr/bin/python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --self-test
</pre>

Trois choses : la passe toutes les 15 minutes <b>en simulation</b>, cette même ligne avec `--live` mais commentée, et une vérification quotidienne que la configuration et les barrières restent saines.

> [!WARNING]
> Si le fichier sort vide, c'est que cet `install` n'a pas été exécuté. Ne l'écris pas à la main : relance-le. Et s'il proteste en disant qu'il ne trouve pas la source, c'est que le `cp -a` de la section 3.5.4 n'a pas copié le dossier `cron.d`.

Laisse-le ainsi quelques jours, examine le journal et **seulement alors** passe en mode réel. Le changement consiste à commenter une ligne et à décommenter l'autre, et le faire à la main, c'est justement là qu'on laisse les **deux** actives (double envoi) ou **aucune** (on cesse de signaler, en silence). C'est pourquoi on le fait avec une commande et non en modifiant le fichier.

```bash
sudo sed -i -E 's|^(\*/15 .*malware-watch\.sh)$|#\1|; s|^#(\*/15 .*malware-watch\.sh --live)$|\1|' /etc/cron.d/dirtyland-reporter
```

Et on vérifie. Il doit sortir **une seule** ligne, et avec `--live` :

```bash
grep -vE '^\s*(#|$)' /etc/cron.d/dirtyland-reporter | grep malware-watch
```

<pre>
*/15 * * * * root /opt/dirtyland/platform-reporter/malware-watch.sh --live
</pre>

Pour revenir en simulation, la commande symétrique :

```bash
sudo sed -i -E 's|^(\*/15 .*malware-watch\.sh --live)$|#\1|; s|^#(\*/15 .*malware-watch\.sh)$|\1|' /etc/cron.d/dirtyland-reporter
```

Les deux sont <b>idempotentes</b> : les répéter n'accumule pas de dièses et ne laisse pas deux lignes actives, donc en cas de doute sur le mode de la machine, on lance celle qu'on veut. L'ordre compte : le compte MalwareBazaar a déjà été perdu une fois pour avoir publié avant de vérifier. Et il tourne toutes les 15 minutes et non toutes les 3, car les échantillons sont jugés des heures après leur capture, donc regarder plus souvent ne fait que consommer du quota ; un `flock` empêche que deux passes se chevauchent.

### 3.5.9 Surveillance, pause et que faire si on te bannit.

Ce qui a été envoyé et ce qui a été refusé, d'un seul coup :

```bash
sudo tail -n 40 /var/log/dirtyland-reporter/reporter.log
```

Et si tu veux <b>rester à regarder</b> pendant qu'une passe tourne, avec `-f`. Attention : celui-ci ne se termine pas tout seul, il reste à attendre de nouvelles lignes jusqu'à ce que tu le coupes avec `Ctrl+C`.

```bash
sudo tail -f /var/log/dirtyland-reporter/reporter.log
```

Et deux options pour quand quelque chose ne colle pas. Avec `-v`, la journalisation passe en `DEBUG` et les éléments écartés apparaissent un par un au lieu du résumé :

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini -v
```

Et avec `--only`, on ne collecte que depuis un seul leurre, ce qui est la façon rapide de savoir lequel des deux est silencieux :

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --only dionaea
```

Si le processus meurt entre l'envoi et sa confirmation, cette intention reste enregistrée sur disque et l'envoi <b>n'est pas réessayé à l'aveugle</b> à la passe suivante. Renvoyer par précaution, c'est exactement comme cela que se créent les doublons que les plateformes pénalisent.

Chaque plateforme le résout comme elle peut, et **aucune ne devine** :

| | Comment c'est résolu |
|---|---|
| MalwareBazaar | `get_info` dit si le hash est arrivé. Il tranche dans les deux sens |
| ThreatFox | `search_ioc` de même. Si la réponse n'est pas comprise, cela reste en vol |
| VirusTotal | Les **soumissions**, en consultant le hash. Les commentaires et les votes, non : il n'y a pas de moyen peu coûteux de le savoir, et se tromper laisserait un doublon sur un échantillon d'autrui |
| URLhaus | Il n'agit que s'il dit qu'il l'a **bien**. Un "je ne l'ai pas" **ne** la libère **pas** (nous n'avons jamais utilisé cette API et nous ne savons pas si une URL fraîchement envoyée se voit immédiatement ; la tenir pour perdue la dupliquerait) |
| AbuseIPDB | On ne le consulte pas, et ce n'est pas nécessaire : la clé contient la date, donc la laisser en vol se comporte comme la fenêtre de refroidissement de 24 h. Demain, la clé change et le signalement repart |

Et ce que personne ne résout ne reste pas pour toujours : une ligne en vol empêche cette clé de partir, donc au bout de `inflight_max_age_hours` (24) la ligne est tenue pour perdue et la clé redevient disponible.

> [!IMPORTANT]
> <b>Un `timeout` ou un `500` au milieu d'une publication ne signifient pas "ce n'est pas arrivé", ils signifient "on ne sait pas".</b> Le serveur a pu la traiter et tomber en répondant, donc la répéter publie la même chose deux fois. C'est arrivé avec un signalement en double à AbuseIPDB, qui a répondu `You can only report the same IP once in 15 minutes`.
>
> C'est pourquoi chaque requête déclare si elle publie ou si elle ne fait que lire, et le transport les traite différemment :
>
> | | lecture | publication |
> |---|---|---|
> | `429` | réessaie | réessaie : il est émis avant le traitement, donc rien n'a été créé |
> | `5xx` | réessaie | non, c'est ambigu |
> | réseau coupé | réessaie | non, c'est totalement ambigu |
>
> L'ambigu ne compte ni comme un succès ni comme un refus, mais comme <b>non confirmé</b>, qui est un groupe à part du résumé quotidien : l'intention reste dans `inflight` pour pouvoir découvrir ensuite ce qui s'est passé, et la passe suivante ne la renvoie pas. Ce n'est pas bloqué pour toujours, car la clé d'AbuseIPDB contient la date. Et `test_gates.py` parcourt le code en vérifiant qu'aucune requête ne reste non déclarée, car marquer les neuf endroits d'aujourd'hui ne sert à rien si le dixième est écrit demain sans le drapeau.

### Ce qui se passe si VirusTotal cesse d'être disponible

Toute la chaîne dépend de son verdict : sans lui, on ne peut pas établir que quelque chose est du malware, donc <b>rien n'est publié sur aucune autre plateforme</b>. Les échantillons restent dans la file avec leur état et chaque passe réessaie, et quand VirusTotal revient, ils sont jugés et publiés normalement.

Le cas le plus important est de se retrouver sans quota, car c'est le seul qui peut arriver en usage normal. Ce sont <b>500 appels par jour</b>, et les consultations de hash, qui sont la majorité, y entrent aussi :

- Le compteur est dans la base d'état et il est incrémenté dans le <b>transport</b>, au seul endroit qui ouvre un socket. Il n'y a aucun moyen de consommer un appel sans qu'il soit compté.
- Avant chaque requête, on vérifie, et on réserve trois appels de marge. Ainsi, il n'arrive pas qu'un échantillon soit soumis et que nous nous retrouvions sans quota juste avant de le commenter, ce qui est la brèche qu'exploitent les bots.
- Une fois le quota épuisé, <b>on cesse de demander</b>. Insister ne ferait qu'accumuler des réponses `429`, et c'est ce qui précède une suspension.
- L'exécution se termine avec le <b>code 5</b> et laisse dans le journal le nombre d'échantillons en attente.

<pre>
virustotal: 500/500 llamadas hoy. Quedan 3 muestras en espera; no se publicara
nada hasta que la cuota se renueve, y eso es lo correcto: sin veredicto de
VirusTotal no se puede acreditar que algo sea malware.
</pre>

> [!CAUTION]
> <b>MalwareBazaar, ThreatFox et URLhaus dépendent du même compte abuse.ch.</b> Une sanction sur l'une des trois emporte les deux autres, donc c'est un seul risque pour les trois. C'est pourquoi les refus ne sont pas comptés par plateforme mais <b>par compte</b>.

Il y a un <b>disjoncteur</b> monté là-dessus : trois refus d'abuse.ch en 24 heures, d'où qu'ils viennent, et les trois plateformes s'éteignent toutes seules. Et elles restent éteintes, car se réarmer seul reviendrait à provoquer de nouveau le service même qui vient de dire non. Quand il saute, cela se voit dans le journal et dans le `--self-test`, avec le motif du dernier refus, et on le réarme à la main après avoir compris ce qui s'est passé :

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --reset-breaker
```

VirusTotal et AbuseIPDB ne sont pas affectées par ce disjoncteur : ce sont des comptes indépendants et elles continuent de fonctionner.

Pour cesser d'envoyer à abuse.ch tout en continuant avec AbuseIPDB et VirusTotal, il suffit de désactiver ces sections du `config.ini` :

```ini
[malwarebazaar]
enabled = false

[threatfox]
enabled = false

[urlhaus]
enabled = false
```

Et pour tout arrêter sans rien démonter :

```bash
sudo rm /etc/cron.d/dirtyland-reporter
```

Si le bannissement arrive, abuse.ch accepte les recours. Ce qui fonctionne, c'est d'expliquer sans fioritures ce qu'est la machine, ce qui a causé l'infraction et ce qui a été changé pour que cela ne se reproduise pas.

### 3.5.10 Vérifier que les portes fonctionnent toujours.

Dans `tests/`, il y a deux batteries qui vérifient que chaque règle de cette section est réellement respectée. Elles n'ont besoin ni de clés, ni de réseau, ni de honeypot : elles remplacent `requests` par une doublure, donc on peut les exécuter à tout moment et sur n'importe quelle machine.

```bash
sudo python3 /opt/dirtyland/platform-reporter/tests/test_gates.py
```

Elle vérifie les portes une par une : qu'avec 4 moteurs on ne publie pas, que 12 génériques sans famille non plus, qu'un échantillon de 30 jours est refusé, que sans `first_submission_date` on ne soumet pas (la cause du bannissement), que le même hash ne part pas deux fois, qu'un `arm` répété de la même campagne est écarté mais pas un `mips`, que sans handshake on ne signale pas à AbuseIPDB et qu'une IP à nous fait avorter l'envoi.

```bash
sudo python3 /opt/dirtyland/platform-reporter/tests/test_end_to_end.py
```

Elle monte un `cowrie.json` et une `dionaea.sqlite` factices avec le vrai schéma, exécute l'orchestrateur complet et vérifie ce qui ne se voit pas en lisant le code : que la chaîne part dans le bon ordre (**VirusTotal avant MalwareBazaar**), qu'une deuxième passe ne répète rien, que les codes de sortie distinguent les cas et qu'aucune IP à nous ni aucune clé n'apparaît dans ce qui aurait été envoyé.

Les deux se terminent avec le <b>code 0</b> si tout passe, et listent ce qui échoue sinon. Il faut les lancer après avoir touché à n'importe quel seuil ou politique, et aussi après une réinstallation de la machine : elles prennent quelques secondes.

L'une des barrières de ce reporter a été <b>cassée sans que personne ne le remarque</b>, car un caractère de trop dans une comparaison la rendait sans effet et rien n'échouait. Les tests existent pour cela.

## 3.6 Pour nous faciliter la vie.

Il y a des actions que l'on finira sans doute par faire de nombreuses fois :
- Entrer dans le leurre pour voir comment il se comporte.
- Tout arrêter quand quelque chose tourne mal.
- Etc.

Comme nous ne voulons obliger personne à apprendre des commandes ni à ouvrir cette documentation.<br>
J'ai décidé de créer ces scripts, qui regroupent toutes les actions possibles que j'ai pu faire sur le serveur :

| Script | À quoi il sert |
|---|---|
| `acceder_ssh_para_vagos.sh` | Entrer dans le leurre depuis l'intérieur du VPS lui-même |
| `boton_del_panico.sh` | Arrêter net les deux conteneurs, et les relancer |
| `cortar_el_grifo.py` | Couper la publication vers une plateforme précise, et le mode du cron |
| `estoy_dentro.py` | Faire taire les alertes de l'hôte pendant que tu travailles sur la machine |
| `que_pasa_con_las_plataformas.py` | Plateforme par plateforme : ce qui a été publié, ce qui a été écarté et **pourquoi** |
| `voy_al_dia.py` | Quelle version est en place sur le VPS et si elle correspond à la copie du dépôt |
| `que_le_falta_al_senuelo.py` | Quels binaires le leurre **dit avoir** sans savoir les exécuter, triés selon ce que les bots ont réellement tapé |
| `banco_shell_real.py` | Fait passer des lignes par le **vrai shell**, le protocole de Cowrie sur son `fs.pickle`, et compare avec ce que répond `bash`. Sans réseau et sans toucher au VPS. Il couvre ce que les tests de commandes ne peuvent pas voir : le découpage, la redirection, les parenthèses et le répertoire courant. **403 cas au vert**, et les cas ouverts sont dans une liste à part |

Ces fichiers se trouvent dans le dossier `3.6 Para facilitarnos la vida/` du dépôt.<br>
On les copie :

```bash
install -m 700 -t ~/ "/tmp/dirtyland-repo/3.6 Para facilitarnos la vida/"*.sh "/tmp/dirtyland-repo/3.6 Para facilitarnos la vida/"*.py
```

Un joker et non la liste des noms, pour qu'ajouter un script dans ce dossier n'oblige pas à toucher cette étape. Les `tests/` n'y entrent pas, car le joker ne descend pas dans les sous-répertoires. Et c'est `700` parce que l'un de ces scripts éteint tout le leurre et qu'un autre touche au `config.ini`.

```bash
ls -l ~/*.sh ~/*.py
```

Les neuf doivent apparaître en `-rwx------` : les huit du tableau et `que_hizo_esta_ip.py`, expliqué au 3.9.

### 3.6.1 Brève explication du fonctionnement de chaque commande.

#### Entrer dans le leurre.

Sans argument, il entre en tant qu'`alyosha` ; on peut lui passer un autre utilisateur du `userdb` :

```bash
~/acceder_ssh_para_vagos.sh
```

```bash
~/acceder_ssh_para_vagos.sh admin
```

Il ne demande pas le mot de passe, il le saisit lui-même. Pour tester une connexion <b>échouée</b>, par exemple pour voir si l'alerte se déclenche, on lui demande de le demander :

```bash
~/acceder_ssh_para_vagos.sh admin --pedir
```

Il se connecte au conteneur <b>depuis l'intérieur du VPS</b>, donc la session n'est pas confondue avec une attaque. Il faut OpenSSH 8.4 ou plus récent.

#### Le bouton panique.

Il arrête les deux conteneurs, et avec eux toute l'activité entrante. Il faut `sudo`, et il demande de confirmer en tapant `PARAR` :

```bash
sudo ~/boton_del_panico.sh
```

```bash
sudo ~/boton_del_panico.sh --estado
```

```bash
sudo ~/boton_del_panico.sh --reanudar
```

Il ne touche pas au pare-feu, n'efface rien, et le reporter continue de traiter ce qui a déjà été recueilli.

#### Couper le robinet d'une plateforme.

Il arrête la publication vers une plateforme précise pendant que tu règles une question avec elle. Il faut `sudo`, car il modifie le `config.ini` :

```bash
sudo ~/cortar_el_grifo.py
```

<pre>
Current status:
  0)  cron mode  (/etc/cron.d/dirtyland-reporter)      🔴 SIMULATION  (nothing is published)

  1)  abuse.ch  (MalwareBazaar + ThreatFox + URLhaus)  🔴 stopped
  2)  VirusTotal                                       🔴 on, but muted by cron
  3)  AbuseIPDB                                        🔴 on, but muted by cron

  [REASON: cron is in SIMULATION mode: nothing is published]
</pre>

On bascule par numéro, et on peut en donner plusieurs (`0 1`). Avant de confirmer, il montre ce qui va se passer et laisse une copie datée du `config.ini`. <b>L'option 0 est le mode du cron</b> et elle l'emporte sur tout le reste : avec lui en simulation, rien n'est publié. Seule la <b>publication</b> est coupée : le leurre continue de capturer et le reporter de recueillir.

Un état 🟡 `PARTIAL` se résout en <b>éteignant</b>, pas en allumant :

| État actuel | En la choisissant |
|---|---|
| 🟢 les trois allumées | les trois s'éteignent |
| 🟡 certaines allumées | les trois s'éteignent |
| 🔴 aucune allumée | les trois s'allument |

Pour seulement regarder, sans rien changer :

```bash
sudo ~/cortar_el_grifo.py --estado
```

#### Faire taire les alertes pendant que tu es dedans.

Quand c'est toi qui entres sur la machine, tout ce que tu fais déclenche des alertes. Ceci les fait taire. Il faut `sudo`, car il écrit dans `/opt/dirtyland/monitor/` :

```bash
sudo ~/estoy_dentro.py
```

```bash
sudo ~/estoy_dentro.py --estado
```

| Ce qu'il fait taire | Ce qu'il **ne** fait **pas** taire |
|---|---|
| Tout ce qui passe par `send-alert.sh` : le surveillant SSH, celui des commandes, celui du pare-feu et celui de Dionaea. Autrement dit, la surveillance de l'hôte | Le **résumé quotidien**, qui est envoyé avec `--siempre` exprès |
| | Le chat du **leurre** : ce sont deux bots et deux conversations différentes (section 3.4.2.7) |
| | Le leurre lui-même. Cowrie et Dionaea continuent de capturer, et le reporter continue de publier. Pour les arrêter, il y a `~/boton_del_panico.sh` |

Par défaut, il fait taire les alertes <b>4 heures</b>, puis la surveillance se rallume toute seule. On peut demander un silence sans limite en tapant `forever`. Les alertes mises en silence ne sont pas perdues : elles sont notées et le résumé quotidien les compte.

```
Vigilancia del anfitrion
🔴 SILENCIADA --- vuelve sola en 143 min
  🟡 6 aviso(s) retenidos en /opt/dirtyland/monitor/silenciadas.log
```

#### Savoir si ce qui est en place est ce qui est dans le dépôt.

Il faut `sudo`, car presque tout ce qui est déployé appartient à `root` :

```bash
sudo ~/voy_al_dia.py
```

<b>Il faut le lancer avant d'exposer.</b> Il compare la version en place sur le VPS avec celle de la copie que le `git archive` a laissée dans `/tmp/dirtyland-repo` :

<pre>
en la maquina : 7f0e389  2026-08-28T06:50
en la copia   : 7f0e389  2026-08-28T06:50
AL DIA
</pre>

S'ils ne correspondent pas, il dit `ATRASADO`, et la première fois, avec la machine pas encore marquée, `SIN MARCAR`. Il ne change rien. Il renvoie `0` s'ils correspondent, `1` si elle est en retard ou non marquée et `2` s'il n'a pas pu comparer, par exemple parce que le dossier a été envoyé à la main au lieu de passer par `git archive`.

#### Ce que le leurre dit avoir sans savoir l'exécuter.

Il faut `sudo`, car il lit le `fs.pickle` et les journaux de Cowrie, et interroge le conteneur :

```bash
sudo ~/que_le_falta_al_senuelo.py
```

Le système de fichiers du leurre annonce des centaines de binaires qu'il ne sait pas exécuter, et c'est une contradiction qui n'arrive sur aucun Linux :

<pre>
$ ls -la /usr/bin/sed   ->  -rwxr-xr-x 1 root root 126424 Jan  5 2023 /usr/bin/sed
$ file /usr/bin/sed     ->  ELF 64-bit LSB pie executable, x86-64
$ which sed             ->  /usr/bin/sed
$ sed --version         ->  -bash: /usr/bin/sed: No such file or directory
</pre>

Le script trie ce qui manque selon ce que les bots ont réellement tapé contre ce leurre, il dit donc ce qu'il vaut mieux émuler en premier :

<pre>
  SABE EJECUTAR        : 196 nombres
  DICE TENER           : 453 binarios
  DICE TENER Y NO SABE : 353   (78% de lo que anuncia)

QUE EMULAR PRIMERO --- lo que falta y ADEMAS se ha tecleado aqui
      12  sed                      /usr/bin/sed
       7  ln                       /usr/bin/ln
       5  sysctl                   /usr/sbin/sysctl

Y 350 que tampoco sabe ejecutar pero NADIE ha tecleado.
</pre>

```bash
sudo ~/que_le_falta_al_senuelo.py --tecleado
```

```bash
sudo ~/que_le_falta_al_senuelo.py --todos
```

- Le premier montre seulement le classement de ce qui est le plus tapé, avec une marque sur ce que le leurre ne sait pas exécuter.
- Le second liste en plus ceux que personne n'a jamais tapés.

#### Savoir si tu es à jour.

C'est ce qui permet à `voy_al_dia.py` de savoir la prochaine fois quelle version est en place :

```bash
sudo ~/voy_al_dia.py --marcar
```

> [!IMPORTANT]
> <b>C'est la dernière étape de tout déploiement, et la seule dont il faut se souvenir.</b> Ce qu'il ne détecte pas : si tu copies certaines pièces et pas d'autres, il dira quand même que tu es à jour, car il ne regarde que le sceau.

#### Autres scripts.

Oui, je ne les ai pas tous mis, car les trois qui manquent sont au 3.9.

## 3.7 Dernières vérifications avant d'exposer.

Comme nous sommes si paranoïaques et rigoureux dans notre travail, nous devons confirmer :

### 3.7.1 Les deux canaux d'alerte fonctionnent.

Si nous exposons le leurre et que les alertes ne fonctionnent pas, nous passerons justement à côté de ce pour quoi nous avons monté tout cela.

Ceci est la vérification rapide (que les deux bots parlent). La répétition complète, alerte par alerte, se trouve dans les deux sections suivantes.

Le bot de l'<b>hôte</b> :

```bash
sudo /opt/dirtyland/monitor/send-alert.sh "Comprobacion previa a la exposicion"
```

Et le bot du <b>leurre</b>, en provoquant un vrai événement depuis l'intérieur (le honeypot reste scellé, donc on se connecte directement au conteneur par son IP interne) :

```bash
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null alyosha@172.20.0.10
```

Une fois dedans, n'importe quelle commande devrait nous déclencher une alerte sur le Telegram de Cowrie :

```bash
whoami
exit
```

### 3.7.1.1 La répétition complète : les vingt-cinq alertes.

Que les deux bots parlent ne veut pas dire que **toutes** les alertes arrivent. Chacune est composée par un surveillant différent, avec son propre HTML, ses drapeaux et son découpage, donc un défaut de format dans l'une ne dit rien des autres.

`probar-avisos.sh` les déclenche toutes, l'une après l'autre. **Vingt-deux viennent de l'hôte** et il les monte lui-même avec de fausses entrées ; les **trois dernières viennent du leurre** et nécessitent une vraie session, donc elles passent à la fin et sont expliquées un peu plus bas :

```bash
sudo /opt/dirtyland/monitor/probar-avisos.sh
```

Cela prend environ une minute (il attend trois secondes entre chaque message pour ne pas se heurter à la limite de Telegram) et parcourt ces vingt-cinq, dans cet ordre :

<pre>
 1  [Host] Login SSH exitoso
 2  [Host] INTENTO DE ACCESO A ROOT
 3  [Host] Intento de login SSH FALLIDO
 4  [Dirtyland] Ordenes tecleadas (comandos-watch)
 5  [Dirtyland] Ordenes vistas por auditd
 6  [Dirtyland] Cortacircuitos SALTADO
 7  [Dirtyland] Cortacircuitos rearmado
 8  [Dirtyland] Cuota superada
 9  [Dirtyland] Cuota restablecida
10  [Dirtyland] IP's baneadas (parte diario)
11  [Dirtyland] Resumen diario (datos reales de la maquina)
12  [Dirtyland] Tabla de paises: no se pudo regenerar
13  [Dirtyland] Tabla de paises: los datos llegaron incompletos
14  [Proxy] Inactivo al arrancar (primera pasada)
15  [Proxy] Un relay se cae
16  [Proxy] Y vuelve
17  [Proxy] Un relay desaparece de la lista de Mullvad
18  [Proxy] Queda uno solo: acceso sin respaldo
19  [Proxy] SIN ACCESO: se caen todos
20  [Dionaea] Nuevas conexiones de ataque + malware capturado
21  [Dionaea] Vivo pero mudo (sin anotar nada)
22  [Dionaea] Vuelve a anotar conexiones

23  [Cowrie via SSH] Login correcto + ACTOR NUEVO con sus ordenes
24  [Cowrie] MUESTRA NUEVA (fichero vacio, e3b0c442...b855)
25  [Cowrie via Telnet] Login correcto
</pre>

Les trois dernières viennent **du leurre**, et aucun surveillant de l'hôte ne les compose : c'est le plugin qui vit dans Cowrie qui les compose, et il ne parle que lorsqu'il y a une session. Donc pour elles, on ne falsifie pas l'entrée (on entre vraiment, on tape et on téléverse un fichier), et elles arrivent ainsi sur le téléphone :

<pre>
[Cowrie vía SSH]     Event: cowrie.login.success
[Cowrie vía SSH]     ACTOR NUEVO / GUION NUEVO   (con los comandos, a los 30 s)
[Cowrie]             MUESTRA NUEVA  SHA256: e3b0c442...b855
[Cowrie vía Telnet]  Event: cowrie.login.success
</pre>

Sur le téléphone arrivent <b>un peu plus de vingt-cinq messages</b>, car certaines étapes en déclenchent plusieurs et c'est ce qui se passerait en vrai : la 19 envoie un "caído" pour chaque relais et le "SIN ACCESO" qui les résume, et la 4 envoie une série pour chaque utilisateur qui était en train de taper.

Si l'une n'apparaît pas, c'est son surveillant qui échoue et il faut le regarder **avant** d'exposer. Le terminal indique où il en est, donc celle qui manque s'identifie d'elle-même.

Un `send-alert.sh hola` ne testerait que le token. Ici, chaque alerte est composée par le vrai code, avec des données factices, donc ce qui arrive sur le téléphone est exactement ce qui arrivera le jour où cela se produira.

Et cela ne touche à rien de la production. Tous les surveillants acceptent, par variable d'environnement, l'emplacement de leur état et de ce qu'ils lisent, et la répétition les pointe vers un répertoire temporaire qui est effacé à la sortie : aucun compteur n'avance, aucune IP n'est marquée comme ayant fait l'objet d'une alerte. Le seul qui tourne avec des données réelles est le résumé quotidien.

Les relais ne sont pas écrits en dur non plus : les six alertes du proxy viennent de la lecture de `proxys.conf`, qui est l'endroit où le surveillant les lit, et le drapeau est déduit des deux premières lettres du nom du relais.

Et si on ne veut en répéter qu'une (parce qu'elle a échoué, ou parce qu'on vient de toucher ce surveillant), on la demande par son numéro :

```bash
sudo /opt/dirtyland/monitor/probar-avisos.sh --solo 14
```

> [!WARNING]
> <b>Celles-ci laissent bien une trace, contrairement aux vingt-deux précédentes.</b> Celles-là sont montées dans un répertoire temporaire et ne touchent à rien ; celles-ci sont de vraies sessions contre le leurre, donc elles restent dans la base de Cowrie, dans le journal des commandes et dans `downloads/`, et apparaîtront ensuite dans le rapport d'analyse. C'est pourquoi elles sont derrière leur propre option.

Trois détails sur cette série. Le fichier téléversé est le <b>fichier vide</b>, dont le SHA-256 est `e3b0c442...b855` : un hash réel, inoffensif et qui existe dans VirusTotal, donc le lien de l'alerte peut être suivi jusqu'au bout. Il y a deux téléchargements exprès, car Dionaea ne note que le MD5 dans sa base et il faut voir les deux formes du message. Et la répétition écrit dans la base de Dionaea, donc elle laisse des lignes factices que le résumé du lendemain compterait.

Le bouton "Block IP" se teste à part, sur le moment : il arrive dans le résumé quotidien, on appuie dessus depuis le téléphone et il doit répondre `🚫 BLOCKED` dans le même message. Cela parcourt tout le chemin, le plugin, la file, le `sudo` de l'hôte et `nft`, et cet appui vient de ton doigt, donc il n'y a pas de script qui le répète.

Deux alertes de Cowrie ne sortent pas dans cette répétition, et ce n'est pas une question d'attendre plus longtemps : le bannissement automatique et le résumé de ce qui a été mis en sourdine ne peuvent pas sortir d'ici, car ils sont composés par le plugin dans le conteneur et dépendent d'un vrai trafic accumulé. On les voit au 3.8.2, quand il y a déjà quelqu'un pour les provoquer.

Les deux arrivent toutes seules dès que le leurre a été exposé un certain temps. Si tu ne veux pas attendre les deux cents répétitions du bannissement ni la demi-heure du résumé, les seuils sont lus dans l'environnement et peuvent être abaissés les premiers jours dans le `docker-compose.yml` :

```
    environment:
      - TZ=Europe/Kyiv
      - AUTOBAN_REPETICIONES=20
      - DIGEST_INTERVAL=300
```

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml up -d cowrie
```

Quand tu les as vues, on retire les deux lignes et on relance de la même façon. En production, les bonnes valeurs sont celles d'origine.

### 3.7.2 Les services de surveillance sont actifs.

```bash
sudo systemctl status dirtyland-sshwatch.service --no-pager
sudo systemctl status dirtyland-cmdwatch.service --no-pager
sudo systemctl status cron --no-pager
sudo crontab -l | grep -v -e '^#' -e '^$'
```
<i>J'ai ajouté un `grep -v` pour retirer les commentaires : si le crontab de root a déjà été ouvert avec `crontab -e`, il contient un en-tête de 23 lignes.</i>

Les trois doivent afficher : 
- `active (running)` et `enabled; preset: enabled`.
- Et que le journal des commandes est en place : `/etc/profile.d/dirtyland-registro.sh` doit exister avec le mode `644`, **et `grep -c dirtyland-registro /etc/bash.bashrc` doit donner `1`**. Sans le premier, `dirtyland-cmdwatch` tourne en surveillant un canal vide. Sans le second, tout ce qui est tapé dans un shell root ouvert avec `sudo su` est perdu.
- `sudo crontab -l` doit afficher <b>cinq</b> lignes. On utilise `sudo` parce que c'est là qu'elles ont été installées au 3.4.4 : le crontab de ton utilisateur est vide et `crontab -l` seul répond "no crontab for user", ce qui donne l'impression que tout manque alors que rien ne manque.

| Tâche | Ligne | Si elle manque |
|---|---|---|
| Résumé quotidien | `0 6 * * * /opt/dirtyland/monitor/daily-digest.sh` | |
| Surveillance de Dionaea | `*/5 * * * * /opt/dirtyland/monitor/dionaea-watch.sh` | Les attaques par SMB, RPC et MSSQL ne sont pas notifiées : Dionaea n'a pas de plugin d'alertes comme Cowrie |
| IP bannies | `0 6 * * * /opt/dirtyland/monitor/baneadas-diario.sh` | |
| Proxys d'accès | `*/30 * * * * /opt/dirtyland/monitor/proxy-watch.sh` | Le jour où Mullvad retire un relais, tu l'apprends quand tu ne peux plus entrer |
| Table des pays | `0 4 1,16 * * /opt/dirtyland/geoip/generar-tabla-paises.py --avisar` | Les drapeaux des alertes deviennent peu à peu obsolètes sans que rien ne le dise |

### 3.7.3 Les conteneurs sont démarrés et en bonne santé.

```bash
sudo docker ps
```

Les deux (`dirtyland_cowrie` et `dirtyland_dionaea`) doivent apparaître à l'état `Up`, et aucun à `Restarting` (ce qui indiquerait que quelque chose échoue en boucle).

On vérifie aussi que Cowrie a chargé ses deux moteurs de sortie et qu'il n'y a pas d'erreurs de chargement du système de fichiers :

```bash
sudo docker logs dirtyland_cowrie --tail 20
```

### 3.7.4 Savoir exactement ce que nous exposons.

C'est la vérification la plus importante de toutes : <b>ce qui écoute, sur quel port et sur quelle IP</b>.

```bash
sudo ss -tulnp
```

Ce qui doit sortir, et rien d'autre :

| IP | Port | Service | Qui c'est |
|---|---|---|---|
| `[IP VPS]` | 22 | SSH | Cowrie (leurre Linux) |
| `[IP VPS]` | 23 | Telnet | Cowrie (leurre Linux) |
| `[IP VPS 2]` | 135 | RPC | Dionaea (leurre Windows) |
| `[IP VPS 2]` | 445 | SMB | Dionaea (leurre Windows) |
| `[IP VPS 2]` | 1433 | MSSQL | Dionaea (leurre Windows) |
| `0.0.0.0` | 56769 | SSH | <b>Notre vraie administration</b> |

> [!WARNING]
> Si <b>n'importe quel autre port</b> apparaît en écoute sans être dans cette liste, il faut découvrir ce que c'est avant d'exposer quoi que ce soit.

Comme c'est un VPS, un port supplémentaire apparaît : le <b>5355</b>, TCP et UDP, qui est le LLMNR de `systemd-resolved`. Il écoute sur toutes les interfaces, mais le pare-feu ne le laisse pas entrer depuis l'extérieur et c'est du trafic de découverte du réseau local, pas un service à nous.

La liste de `ss` montre ce qui écoute sur l'<b>hôte</b>. Les ports des leurres (22 et 23 pour Cowrie ; 135, 445 et 1433 pour Dionaea) n'y apparaissent pas, car avec `"userland-proxy": false` aucun processus ne les occupe : ils sont résolus par DNAT et se vérifient dans la table `nat` de la section suivante.

### 3.7.5 Le docker-compose définitif.

Ici, on ne réécrit pas le fichier : on le **vérifie**. Il vient de la partie 1 du dépôt et son bloc `volumes` a été généré par le script du 3.4.2.9, donc ce qu'il faut faire, c'est confirmer que ce qui est monté est ce qui devrait l'être.

D'abord, que la syntaxe soit valide :

```bash
cd /opt/dirtyland && sudo docker compose config >/dev/null && echo "compose OK"
```

Ce qu'il faut regarder, ce sont les trois choses qui peuvent avoir été oubliées. **Quels ports il publie** :

```bash
cd /opt/dirtyland && sudo docker compose config --format json | python3 -c "import json,sys; [print(f\"{s}: {[p['published'] for p in v.get('ports',[])]}\") for s,v in json.load(sys.stdin)['services'].items()]"
```

<pre>
cowrie: ['22', '23']
dionaea: ['445', '135', '1433']
</pre>

Si le `23` n'apparaît pas dans `cowrie`, le leurre propose du telnet en interne mais personne ne peut l'atteindre, et aucun journal ne le dit (voir le point 4 de la section 3.4.2.10).

**Combien de modules de commandes il monte**, qui doivent être les mêmes que ceux de `cmdpatch` :

```bash
echo "en cmdpatch: $(ls /opt/dirtyland/cowrie/cmdpatch/*.py | wc -l)   montados: $(sudo grep -c 'cmdpatch/.*\.py:' /opt/dirtyland/docker-compose.yml)"
```

Les deux nombres doivent être égaux. Si le second est plus petit, il y a une commande qui existe sur l'hôte et que le conteneur n'utilise pas : on corrige en relançant le générateur du 3.4.2.9 avec `--apply`, pas en modifiant le fichier à la main.

**Et que le fuseau horaire est bien en double**, la variable et le montage :

```bash
sudo grep -E 'TZ=|/etc/localtime' /opt/dirtyland/docker-compose.yml
```

<pre>
      - TZ=Europe/Kyiv
      - /etc/localtime:/etc/localtime:ro
</pre>

### 3.7.6 Les règles du pare-feu sont toujours intactes.

```bash
sudo nft list ruleset
```

Les compteurs de `packets` et `bytes` changent à chaque requête ; ce qui compte, c'est la <b>structure</b>. Il sort plus de tables que celles que nous avons écrites, car Docker crée les siennes au démarrage, et c'est normal.

- <b>`table ip nat`, chaîne `DOCKER`.</b> Le DNAT, avec chaque leurre lié à son IP : `[IP VPS]` vers `172.20.0.10` et `[IP VPS 2]` vers `172.20.0.20`. Il fonctionne déjà.
- <b>`table ip filter`, chaîne `DOCKER`.</b> Docker accepte déjà le trafic entrant vers les cinq ports. De son côté, les leurres seraient joignables.
- <b>`table inet filter`, chaîne `forward`.</b> La nôtre, en `policy drop` et sans règles d'entrée. Les deux tables sont évaluées, donc il suffit que l'une jette le paquet : Docker dit oui, nous disons non, et c'est le non qui l'emporte.
- <b>`table ip raw`.</b> Elle jette le trafic destiné à `172.20.0.10` et `172.20.0.20` qui ne vient pas par le pont, pour que personne ne contourne le DNAT.

C'est la pièce que change la section <b>3.8.2</b> : la partie 4 ajoute les règles d'entrée qui manquent. D'ici là, le leurre reste scellé.

Les quatre tables ci-dessus doivent sortir, avec la `forward` de `inet filter` en `policy drop` et sans règles d'entrée.

Et le plus important, que le pare-feu survive à un redémarrage. Pour le vérifier :

```bash
sudo systemctl is-enabled nftables
```

### 3.7.7 Confirmation finale : nous sommes toujours scellés.

Le test définitif : essayer d'entrer <b>depuis l'extérieur</b>, depuis une machine qui n'est pas le VPS.

```bash
IP1=[IP VPS]; IP2=[IP VPS 2]; for par in "$IP1 22" "$IP1 23" "$IP2 135" "$IP2 445" "$IP2 1433"; do nc -vz -w 3 $par; done
```

Et la même chose depuis PowerShell, la commande du 3.4.1 :

```powershell
$ip1 = '[IP VPS]'; $ip2 = '[IP VPS 2]'; foreach ($prueba in @(@($ip1,22),@($ip1,23),@($ip2,135),@($ip2,445),@($ip2,1433))) { $h,$puerto = $prueba; $t = New-Object Net.Sockets.TcpClient; $abierto = $t.ConnectAsync($h,$puerto).Wait(3000); "{0,-16} {1,-6} {2}" -f $h, $puerto, $(if ($abierto) { 'ABIERTO' } else { 'cerrado o filtrado' }); $t.Close() }
```

Les cinq doivent donner `timed out` (ou `cerrado o filtrado`, si tu l'as fait depuis PowerShell). Si l'un d'eux se connectait, c'est que nous serions déjà exposés sans le savoir.

> [!IMPORTANT]
> Ce test doit être fait <b>deux fois</b> : une fois <b>avec le VPN d'administration connecté</b> (notre IP Mullvad, la seule que le pare-feu autorise sur le port 56769) et une autre fois <b>avec le VPN éteint</b> (en simulant un attaquant quelconque d'Internet). Dans les deux cas, les cinq ports des leurres doivent donner `timed out`. La seule exception légitime est le port d'administration 56769, qui ne doit répondre <b>que</b> lorsque le VPN est connecté et depuis notre IP.

Pendant les tests, un `tcpdump` peut montrer de vrais paquets entrants de scanners automatiques touchant nos IP. C'est le bruit de fond d'Internet et cela ne signifie pas que le leurre est exposé : le pare-feu les jette, ce qui est exactement ce qu'on est en train de vérifier.

### 3.7.8 Les signalements automatiques sont prêts (mais en attente).

On confirme que le reporter est monté et que son bouclier fonctionne, bien qu'encore sans clés d'API (on les met juste avant d'exposer) :

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --self-test
```

Cela doit se terminer par `self-test: todo correcto` et sortir avec le code 0 (la liste de blocage couvre nos trois IP, la barrière bloque ce qu'elle doit et laisse passer ce qu'elle doit). Et que le cron l'a bien programmé :

```bash
grep -r reporter /etc/cron.d/
```

Les clés d'API sont la <b>dernière</b> chose avant d'exposer, pour la raison que donnait déjà le 3.5.5. On les ajoute au `config.ini` au 3.8.1.

### 3.7.9 Dernière recommandation avant l'étape finale.

Avant d'exposer, il est conseillé de faire un <b>snapshot</b> du VPS depuis le panneau du fournisseur, s'il en propose un. Si quelque chose tournait mal après l'exposition, nous pourrions revenir à cet état exact (vérifié et scellé) sans refaire le travail.

> [!CAUTION]
> Une fois toutes ces vérifications passées, la section suivante est l'<b>exposition réelle à Internet</b>. À partir de ce moment, n'importe quel attaquant de la planète peut atteindre nos leurres, et la réputation des deux IP commence à s'user. C'est une étape délibérée et irréversible en ce sens.

### 3.7.10 Les trente-quatre suites, d'un coup.

Tout au long du guide, chaque section exécute les siennes : celles de Telegram au 3.4.2.7 et celles du reporter au 3.5.10. Ceci est la révision complète, **avant d'exposer**, et sert aussi quand on a touché à quelque chose sans se rappeler à quelle section cela appartenait.

Elles n'ont besoin ni de clés, ni de réseau, ni que le leurre soit démarré : elles remplacent les appels HTTP par une doublure et travaillent sur des répertoires temporaires. On les exécute depuis l'arborescence du dépôt, car certaines lisent le fichier qu'elles testent par chemin relatif :

```bash
cd /tmp/dirtyland-repo && find . -path ./.git -prune -o \( -name 'test_*.py' -o -name 'test*.sh' \) -print0 | sort -z | while IFS= read -r -d '' t; do printf '%-30s ' "$(basename "$t")"; case "$t" in *.py) python3 "$t" 2>/dev/null | tail -1 ;; *) bash "$t" 2>&1 | tail -1 ;; esac; done
```

<pre>
test-acceder-ssh.sh            ok: 11   fallos: 0
test_comandos.py               ok: 970  fallos: 0
test_que_hizo_esta_ip.py       ok: 148  fallos: 0
test_gates.py                  test_gates: 382 correctas, 0 fallidas
...                            (34 en total)
</pre>

Et si on ne veut que le verdict, sans parcourir les trente-quatre :

```bash
cd /tmp/dirtyland-repo && fallos=0; total=0; while IFS= read -r -d '' t; do total=$((total+1)); case "$t" in *.py) python3 "$t" >/dev/null 2>&1 ;; *) bash "$t" >/dev/null 2>&1 ;; esac || fallos=$((fallos+1)); done < <(find . -path ./.git -prune -o \( -name 'test_*.py' -o -name 'test*.sh' \) -print0); echo "suites: $total   con fallos: $fallos"
```

<pre>
suites: 34   con fallos: 0
</pre>

Ce que protège chacune, pour savoir ce qui s'est cassé quand l'une échoue :

| Suite | Surveille |
|---|---|
| `test-acceder-ssh.sh` | Que l'assistant d'accès entre **sans rien taper** : le `ssh` du test est factice et exécute le vrai `SSH_ASKPASS`, donc on vérifie le mot de passe qu'il reçoit, que le vrai `userdb` l'emporte sur la copie du script, que l'assistant ne contient pas le secret et qu'il ne reste pas sur le disque |
| `test_parche_protocol.py` | Le mode mot de passe du terminal. Il appuie une par une sur les onze touches d'édition dans un `[sudo] password for ...` et vérifie que **rien n'arrive** au terminal (l'effacement mangeait le prompt, les flèches affichaient l'historique et `Ctrl-L` réaffichait le mot de passe en clair) et qu'en dehors du mode mot de passe toutes continuent de faire ce qu'elles font d'habitude |
| `test_sanitize_pickle.py` | L'assainisseur du système de fichiers : la légende, les `/etc` d'origine, la cohérence de telnet dans ses deux moitiés, le fuseau horaire, les destinations des liens, le `/etc/mtab` qui pointait vers le PID du conteneur de construction et ce même PID dans `/proc` |
| `test-vigilancia-host.sh` | Le journal des commandes de l'hôte et le silencieux : qu'une commande avec `pwd=` écrit dedans ne puisse pas choisir quel répertoire apparaît dans l'alerte, que le silencieux se taise quand il le doit et laisse passer le résumé quotidien, et qu'une alerte sans corps soit quand même envoyée |
| `test_comandos.py` | Les modules de commandes et <b>la cohérence de la légende entre fichiers différents</b> : que `lsblk`, `df`, `/proc/mounts`, `/etc/fstab` et le `dmesg` préenregistré décrivent le même disque, que le `dmesg` utilise le noyau de `/proc/version` et la MAC d'`ifconfig`, et que les sorties préenregistrées tombent dans `usr/bin/` et non dans `bin/`, où elles ne se déclenchent pas |
| `test_gates.py` | Les portes du reporter, une par une, les **deux vetos de politique** de MalwareBazaar, et que les signalements à AbuseIPDB disent la vérité : le port public et non l'interne, et aucune catégorie que les preuves ne soutiennent pas |
| `test_end_to_end.py` | Qu'en simulation, pas une seule publication ne part sur le réseau, et qu'une configuration correcte passe le `--self-test` |
| `test_botones_cowrie.py` | Les boutons de bannissement du bot et les étiquettes de transport (`vía SSH` / `vía Telnet`), et que l'en-tête ne contienne plus le `sensor` |
| `test_memoria_cowrie.py` | Ce que le plugin retient et ce qu'il compte. **La mémoire par IP**, qui décide quand se taire : qu'un script répété alerte une fois et non une fois par session, et qu'en tronquant la mémoire le plugin cesse d'affirmer qu'il n'y a rien de nouveau, car sur une mémoire incomplète on ne distingue pas "il ne l'a jamais fait" de "je l'ai oublié" |
| `test_repetidas_dionaea.py` | **La mémoire qui empêche Dionaea de répéter la même alerte toutes les cinq minutes.** Les deux fonctions sont extraites du script déployé et exécutées avec un vrai `bash`, pas réécrites en Python, car le test vérifierait alors autre chose |
| `test_telnet_opciones.py` | La négociation telnet, celle qui faisait tomber toutes les sessions |
| `test_que_hizo_esta_ip.py` | La fiche d'une IP, sur un leurre synthétique avec deux IP dans le même journal. Surtout, que <b>personne d'autre ne s'y glisse</b>, car une fiche qui mélange deux attaquants n'est pas une erreur de format, c'est un signalement mal fait : il traque les trois endroits par où quelqu'un d'autre pourrait se glisser, y compris une clé similaire que le `LIKE` de SQL fait correspondre. Et les deux choses dont dépend le chiffrement : que le tar ne s'ouvre pas sans la clé et qu'il ne reste pas de `.tar.gz` en clair |
| `test_que_le_falta.py` | Le recensement de ce que le leurre dit avoir sans savoir l'exécuter. Surtout, qu'<b>une commande émulée n'apparaisse jamais comme manquante</b>, ce qui arrivait en lisant le catalogue du `cmdpatch` au lieu de le demander au conteneur |
| `test_paises.py` | Le petit drapeau de chaque IP. Surtout, qu'il <b>ne puisse pas faire tomber une alerte</b> : qu'une table absente, incomplète ou incompréhensible renvoie du vide au lieu d'exploser, ou pire, au lieu de renvoyer deux caractères quelconques ressemblant à un pays. De plus, les bornes de chaque tranche, et que la table soit triée, car c'est de cela que vit la recherche binaire |
| `test_cortar_el_grifo.py` | Que basculer le cron laisse **toujours une seule ligne active**, dans les deux sens |
| `test_que_pasa_con_las_plataformas.py` | Les deux compteurs du jour du rapport par plateforme, qui sont ceux qu'on regarde pour savoir si quelque chose va mal : qu'ils comptent ce qui est d'aujourd'hui et non de toujours, qu'une simulation ne compte pas comme publiée, et que le motif qu'ils écrivent soit le vrai et non un motif générique |
| `test_voy_al_dia.py` | Que le comparateur de déploiements dise la vérité dans les trois états et refuse de valider une copie apportée à la main, dont le sceau arrive non substitué. Et les trois qui veillent à ce que le README ne vieillisse pas : que la liste des suites soit complète, que <b>tout fichier que le README demande de copier existe réellement</b> et qu'il demande toujours de charger le journal des commandes depuis `/etc/bash.bashrc` |
| `test-digest-modo.sh` | La section reporters du résumé quotidien, en entier : que le cron décide de la couleur, les quatre lignes de `[MOTIVO: ...]`, et que les comptes portent sur 24 heures et non sur la dernière passe de quinze minutes |
| `test-lib-telegram.sh` | L'envoi, le découpage des messages et l'échappement HTML |
| `test-ssh-watch.sh` | Le surveillant des accès à l'hôte |
| `test-breaker-watch.sh` | Le disjoncteur du compte abuse.ch |
| `test-cuota-watch.sh` | Le surveillant du quota quotidien : qu'il alerte quand le quota est épuisé et seulement à ce moment-là, qu'il ne se répète pas tant qu'il reste épuisé, qu'au changement de jour cela compte comme une nouvelle transition, et qu'il regarde `api_calls` et non `quota`, car le premier compte les appels, et c'est avec cela que le limiteur compare |
| `test-proxy-watch.sh` | Le surveillant des proxys SOCKS, avec l'API de Mullvad simulée : qu'il alerte quand un relais tombe et quand il revient, qu'il se taise tant que rien ne change, et qu'une réponse bizarre de l'API ne le rende pas muet pour toujours |
| `test-probar-avisos.sh` | La répétition des vingt-deux alertes de la section 3.7.1.1, à sec : que <b>toutes</b> sortent toujours avec l'en-tête qu'écrit chaque surveillant, de sorte que si quelqu'un renomme une alerte sans toucher au guide, ceci passe au rouge ; qu'à sec rien n'est envoyé à Telegram et qu'aucun état de production n'est touché ; et qu'avec une fenêtre de silence ouverte la répétition ne démarre pas |
| `test_analisis.py` | Le rapport de renseignement d'`ANALISIS/analisis.py` sur une sauvegarde <b>synthétique</b>, car on ne peut pas téléverser de vraies captures dans le dépôt : que les scripts soient regroupés (douze IP avec le même script sont un seul acteur, pas douze), que l'heure de Cowrie soit corrigée comme dans le collecteur, que l'illisible soit signalé au lieu de sortir comme un zéro, et que le rapport ne puisse pas finir dans un commit |
| `test-enlaces-malware.sh` | Les liens vers VirusTotal et MalwareBazaar des alertes |
| `test_parche_mssql.py` | La boucle de Dionaea qui bloquait le leurre. Il ne vérifie pas qu'un texte est remplacé par un autre : **il exécute la boucle**, avant et après le correctif, avec le fragment copié lettre par lettre du `mssql.py` de l'image figée par digest, et vérifie que l'une ne se termine jamais et que l'autre, si. Et que le correctif **refuse de s'appliquer** si ce fichier change |
| `test-montajes-dionaea.sh` | Qu'ajouter un montage au `docker-compose` ne torde pas le YAML, car un compose tordu reste du YAML valide et, sans ce montage, Dionaea se bloque de nouveau au premier paquet MSSQL malformé. Il y a deux faux `docker`, l'un qui valide et l'autre qui refuse toujours, car un retour en arrière qui n'a jamais été testé est un retour en arrière dont on ne sait pas s'il existe |
| `test-dionaea-mudo.sh` | Le surveillant de "Dionaea vivant mais muet", le contrôle qui a déjà échoué deux fois en une semaine : cinq jours sans noter une seule connexion alors que `docker ps` disait `Up`, que le processus existait et que le DNAT comptait des paquets. Il vérifie que l'alerte part **au bout de 2 h**, pas le lendemain. Il a besoin du binaire `sqlite3` |
| `test-registro-comandos.sh` | Que ce que tape une personne sur l'hôte soit enregistré, et surtout la **couverture** : un shell root ouvert avec `sudo su` ne notait rien (`/etc/profile.d` n'est lu que par les shells de *login*, et avec `sudo -i` cela fonctionnait, donc la panne dépendait de la façon dont tu devenais root). Il démarre un vrai `bash` de chaque type et y tape des commandes |
| `test_auditd_watch.py` | La lecture du journal d'`auditd`, contre un **véritable échantillon** du VPS et non écrit à la main : les champs interprétés collés au précédent sans espace, les arguments en hexadécimal et un événement réparti sur plusieurs lignes reliées par leur numéro de série |
| `test-cron-dirtyland.sh` | Que les tâches périodiques soient mises en place **sans `nano` et sans doublon**. Cette étape était la seule du déploiement qui n'était pas du copier-coller |
| `test-baneadas-diario.sh` | La liste des IP bloquées et l'origine de chaque bannissement, contre la forme **réelle** d'un `nft list set` : éléments séparés par des virgules, répartis sur plusieurs lignes et suivis de leur commentaire |
| `test-banear-dos-veces.sh` | Appuyer sur le bouton de bannissement d'une alerte dont l'IP est déjà bannie. `nftables` se plaint quand on ajoute un élément qui existe déjà et, avec `set -e`, cela faisait tomber le script, donc le bouton donnait une erreur dans un cas qui n'en est pas une : le résultat recherché est déjà là |

Deux ont besoin du binaire `sqlite3` (`test-dionaea-mudo.sh` et `test-digest-modo.sh`). Sur le VPS, il est présent ; sur une autre machine, il faut l'installer, sinon ces deux-là sont sautées automatiquement, et elles le signalent.

Que les trente-quatre soient au vert **ne dit pas que le leurre va bien** : elles disent que la logique qu'on peut tester sans Internet se comporte comme prévu. Ce à quoi ressemble le leurre depuis l'extérieur se mesure au 3.8.2.

### 3.7.11 Avant de formater ou de déménager la machine : ce qu'il faut sauvegarder.

Presque tout dans ce guide se **régénère** : le pickle, le honeyfs, les modules, le `docker-compose`, les règles du pare-feu. Tout cela vient du dépôt et d'un `docker build`. Mais il y a des choses qui **ne se régénèrent pas** parce qu'elles sont le résultat d'avoir écouté, et celles-là se perdent avec le disque.

> [!CAUTION]
> <b>La base d'état seule ne sert à rien.</b> La table `samples` garde le **chemin** du binaire, pas le binaire. Si tu sauvegardes `state.sqlite3` et pas les volumes Docker, la file des échantillons en attente pointe vers des fichiers qui n'existent plus. Il faut sauvegarder les deux.

Ce qu'il y a, et ce que l'on perd avec chaque chose :

| Quoi | Où | Ce que tu perds s'il disparaît |
|---|---|---|
| État du reporter | `/var/lib/dirtyland-reporter/state.sqlite3` | ce qui a déjà été signalé et soumis, la **file des échantillons en attente de verdict**, les quotas du jour, le disjoncteur et les refus |
| **Malware de Cowrie** | volume `dirtyland_cowrie-var` -> `_data/lib/cowrie/downloads` | les binaires capturés |
| Journal des sessions | même volume -> `_data/log/cowrie/cowrie.json*` | la preuve de tout ce qui s'est passé |
| **Malware de Dionaea** | volume `dirtyland_dionaea-var` -> `_data/lib/dionaea/binaries` | les binaires SMB |
| Événements de Dionaea | même volume -> `dionaea.sqlite` | son journal |
| Mémoire du bot | `/opt/dirtyland/Telegram Reports/state/` | les scripts déjà vus et la liste des bannis |
| Clés d'hôte SSH | `/opt/dirtyland/cowrie/keys/` | l'**empreinte** du leurre, qui changerait |
| Secrets | `config.ini`, `telegram.cfg`, `telegram.env` | les clés d'API et les tokens |
| Règles du pare-feu | dump de `nft list ruleset` | **qui a ordonné chaque bannissement** : automatique ou à la main |

<b>1. Arrêter la pile.</b> Avec les bases de données en cours d'écriture, une copie à chaud peut sortir incomplète :

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml down
```

> [!WARNING]
> `down` tout court. **Jamais `down -v`** : cette option efface les volumes nommés, c'est-à-dire justement le malware et les journaux que tu essaies de sauvegarder.

<b>2. Exporter les règles du pare-feu.</b> Celles de nftables vivent dans le noyau, pas dans un fichier, donc si on ne les exporte pas, elles se perdent au formatage.

```bash
sudo sh -c 'nft list ruleset > /opt/dirtyland/monitor/nftables-ruleset.txt' && sudo chmod 600 /opt/dirtyland/monitor/nftables-ruleset.txt && sudo grep -c BANEADA /opt/dirtyland/monitor/nftables-ruleset.txt
```

Ce décompte est le nombre d'IP bannies avec un commentaire ; s'il sort `0`, c'est que l'export est sorti vide et cela n'a pas de sens de continuer.

> [!NOTE]
> **`sudo nft list ruleset > fichero` ne convient pas** : la redirection est faite par **ton** shell, qui n'est pas root, donc il essaie de créer le fichier sans permissions et, dans un répertoire de root, cela échoue. C'est pourquoi tout va dans `sudo sh -c '...'`.

<b>3. L'empaqueter, le compresser et le chiffrer d'une traite, avec une barre de progression.</b> Les volumes et les chemins de `/opt` vont dans la même archive, pour que la copie soit une seule chose et non trois qu'il faudrait assembler ensuite.

La sauvegarde fait plusieurs Go et `gzip` n'utilise qu'un seul cœur, donc cela prend du temps. Ce script mesure le total, affiche la barre avec son pourcentage et son temps restant, utilise `pigz` (gzip en parallèle) s'il est présent, et **ne laisse aucun `.tar.gz` non chiffré sur le disque**. On le colle tel quel pour le créer :

```bash
cat > ~/respaldo.sh <<'EOF'
#!/bin/bash
# Empaqueta + comprime + CIFRA el respaldo en una sola tuberia, con barra.
# La pila tiene que estar ya parada (pasos 1 y 2 de arriba).
set -e
FECHA=$(date +%F)
OUT=~/dirtyland-respaldo-$FECHA.tar.gz.enc
RUTAS=(
  var/lib/dirtyland-reporter
  var/lib/docker/volumes/dirtyland_cowrie-var
  var/lib/docker/volumes/dirtyland_dionaea-var
  "opt/dirtyland/Telegram Reports/state"
  "opt/dirtyland/Telegram Reports/telegram.cfg"
  opt/dirtyland/cowrie/keys
  opt/dirtyland/platform-reporter/config.ini
  opt/dirtyland/monitor/telegram.env
  opt/dirtyland/monitor/nftables-ruleset.txt
)
command -v pv   >/dev/null || sudo apt-get install -y pv
command -v pigz >/dev/null && GZ=pigz || GZ=gzip
# tamano total, para que la barra tenga porcentaje. Se prefija "/" con un
# bucle: el atajo ${RUTAS[@]/#//} deja las rutas SIN barra y du no las
# encuentra, asi que la barra sale sin total.
ABS=(); for r in "${RUTAS[@]}"; do ABS+=("/$r"); done
TOTAL=$(sudo du -sbc "${ABS[@]}" 2>/dev/null | tail -1 | cut -f1)
sudo tar -cf - -C / "${RUTAS[@]}" \
  | pv -s "$TOTAL" \
  | $GZ \
  | openssl enc -aes-256-cbc -pbkdf2 -salt -k 1234 -out "$OUT"
chmod 600 "$OUT"
ls -lh "$OUT"
EOF
```

Et on l'exécute :

```bash
bash ~/respaldo.sh
```

On vérifie que l'intérieur contient ce qu'il doit contenir (en déchiffrant et en listant, car une archive incomplète se remarque ici) :

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -in ~/dirtyland-respaldo-*.tar.gz.enc -k 1234 | tar -tzf - | grep -cE 'downloads/|binaries/|state.sqlite3'
```

> [!CAUTION]
> Le chiffrement avec le mot de passe "1234" ne cherche pas la confidentialité, mais à ce que Windows Defender ne le détecte pas (et si tu utilises Linux, cela n'a pas d'importance). Windows Defender inspecte toute autre archive, car il cherche et lit des signatures/hashes.

`tar` va prévenir qu'un fichier a changé pendant qu'il le lisait, et c'est normal : le leurre écoutait encore il y a un instant et `cowrie.json` a pu grossir entre le moment où `tar` l'a ouvert et celui où il l'a terminé. Il sort avec le code 1, qui est un "avertissement", pas une "erreur" : l'archive est complète et peut être restaurée.

<b>4. Redémarrer la pile et récupérer l'archive chiffrée</b>, depuis ton ordinateur et avec le VPN connecté.

La sauvegarde est faite, donc **on redémarre le leurre** pour qu'il ne reste pas plus longtemps arrêté (seulement si tu NE vas PAS formater tout de suite ; si tu formates juste après, saute cette étape) :

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml up -d
```

Le script a laissé le `.enc` dans ton propre `home` et il t'appartient déjà, donc on le télécharge directement. <b>Depuis ton ordinateur</b> (cela vaut aussi bien sous PowerShell que sous Linux ; `scp` utilise le même `~/.ssh/config` du 3.2.6, donc si un relais du proxy est tombé, on passe à l'alias de l'un des relais de secours) :

```bash
scp dirtyland:~/dirtyland-respaldo-*.tar.gz.enc .
```

Une fois que tu l'as téléchargé, on efface la copie du `home` pour ne pas laisser le malware (même chiffré) à la portée de l'utilisateur normal. <b>Sur le VPS</b> :

```bash
shred -u ~/dirtyland-respaldo-*.tar.gz.enc && echo "copia borrada de la VPS"
```

<b>5. À la restauration</b>, sur la nouvelle machine : on suit le guide jusqu'à avoir démarré la pile une fois (pour que Docker crée les volumes avec leur nom) et **alors** on l'arrête, on restaure par-dessus et on la redémarre :

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml down
```

On déchiffre et on extrait dans un seul pipe (le fichier chiffré est d'abord téléversé sur la nouvelle machine, par ex. dans `~`) :

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -in ~/dirtyland-respaldo-FECHA.tar.gz.enc -k 1234 | sudo tar -xzf - -C /
```

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml up -d
```

Et la première chose à regarder ensuite, car c'est ce qui dit si la file a survécu :

```bash
sudo python3 -c "import sqlite3
for r in sqlite3.connect('/var/lib/dirtyland-reporter/state.sqlite3').execute('SELECT state, COUNT(*) FROM samples GROUP BY state'): print(r[0], r[1])"
```

Si tu décides de **ne pas restaurer** et de repartir de zéro, rien de grave ne se passe, mais cela implique ceci : les IP déjà signalées seraient signalées de nouveau, et les échantillons déjà soumis seraient réessayés pour que les plateformes les refusent comme doublons. Ce n'est pas un bannissement, mais c'est du bruit évitable.

## 3.8 Exposition.

Jusqu'ici, tout le travail a été fait avec le leurre scellé. Cette section est celle qui l'ouvre à Internet, et il n'y a que deux étapes : mettre les clés d'API et appliquer la partie 4 du pare-feu. Dans cet ordre, car les clés ne présentent aucun risque avec la machine fermée, alors que le pare-feu, lui, est le point de non-retour.

> [!CAUTION]
> À partir du 3.8.2, n'importe qui peut atteindre les deux leurres. La réputation des deux IP commence à s'user et le signalement automatique commence à avoir de quoi parler. Si quelque chose n'a pas été vérifié au 3.7, il faut y revenir maintenant.

### 3.8.1 Clés d'API des signalements.

C'est le dernier changement dans la configuration du reporter, celui qui était en attente depuis le 3.5.5 :

```bash
sudo nano /opt/dirtyland/platform-reporter/config.ini
```

Elles sont toutes ensemble dans `[api_keys]`, au début du fichier, et c'est la <b>seule</b> chose qui reste à remplir. On remplace les trois marqueurs par les vraies clés :

```ini
[api_keys]
virustotal = <CLAVE-API-VIRUSTOTAL>
abusech    = <CLAVE-API-ABUSECH>
abuseipdb  = <CLAVE-API-ABUSEIPDB>
```

Trois clés et non cinq : <b>MalwareBazaar, ThreatFox et URLhaus sont le même compte abuse.ch</b> et partagent l'Auth-Key. C'est la même raison pour laquelle le disjoncteur du 3.5.9 compte les refus par compte et non par plateforme. Qu'elles soient ensemble et au début a un avantage : pour savoir quels secrets contient ce fichier, il suffit de regarder cette section. Et si une plateforme avait un jour besoin d'un compte à elle, on met sa `api_key` dans sa section et celle-ci l'emporte sur celle d'ici.

Le fichier doit rester illisible pour quiconque n'est pas `root`, car à partir de maintenant il contient des secrets :

```bash
sudo stat -c '%a %U:%G %n' /opt/dirtyland/platform-reporter/config.ini
```

Il doit répondre exactement `600 root:root`. Sinon, le reporter refusera de démarrer, ce qui est exactement ce que nous voulons qu'il fasse.

Maintenant, le self-test doit sortir propre pour la première fois :

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --self-test
```

Cela doit se terminer par `self-test: todo correcto` et avec le code 0. S'il se plaint encore d'une `api_key`, c'est que ce marqueur n'a pas été bien remplacé.

Et une passe en simulation, qui cette fois met les clés à l'épreuve :

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini
```

C'est le premier moment où le reporter parle aux plateformes. Avec les clés en place, la simulation fait **bien** les requêtes de lecture ; ce qu'elle ne fait pas, et ne fera pas avant le 3.8.3, c'est publier. Si une clé était fausse, elle apparaîtrait ici comme un `401` dans le journal, et il vaut mieux le découvrir maintenant qu'avec du vrai trafic.

### 3.8.2 Pare-feu final : exposer.

C'est l'étape irréversible. Avant tout, la sauvegarde de ce qui est en place :

```bash
sudo cp /etc/nftables.conf /etc/nftables_3.8.2.pre.exposicion___$(date +%Y-%m-%d_%H:%M:%S).conf.bak
```

> [!WARNING]
> Ouvre **une deuxième session SSH** maintenant et laisse-la connectée pendant que tu fais ceci. Si quelque chose tournait mal avec la chaîne `input`, c'est cette session ouverte qui te permet de corriger ; avec une seule session et le `policy drop`, une erreur te laisse à la porte de la machine.

La règle de la partie 4 est dans le dossier `CORTAFUEGOS` du dépôt, comme les trois précédentes :

```bash
sudo truncate -s 0 /etc/nftables.conf
```

```bash
sudo nano /etc/nftables.conf
```

On y colle le contenu de **[CORTAFUEGOS/nftables-PART-4.txt](CORTAFUEGOS/nftables-PART-4.txt)** et on le relit :

```bash
cat /etc/nftables.conf
```

Quatre choses changent par rapport à la partie 3 :

| Changement | Pourquoi |
|---|---|
| Bloc d'<b>ingress</b> dans `forward` | C'est la seule chose qui expose. Jusqu'ici, le `policy drop` de cette chaîne tuait le trafic qui arrivait par DNAT |
| Interdiction <b>de conteneur à conteneur</b> | Si Cowrie est compromis, il ne doit pas pouvoir toucher le 445 de Dionaea. Sans cette ligne, les règles d'ingress elles-mêmes le lui permettraient |
| La <b>deuxième IP publique</b> dans l'anti-pivot | La partie 3 ne protégeait que `[IP VPS]`. Un conteneur compromis pouvait atteindre `[IP VPS 2]` |
| Suppression du `tcp dport 22 accept` dans `input` | Il n'a jamais rien fait, comme l'expliquait déjà le 3.4.1, et le lire induisait en erreur |

Les ports du bloc d'ingress sont ceux du <b>conteneur</b> (2222 et 2223 pour Cowrie, 135/445/1433 pour Dionaea), pas les ports publiés. Quand le paquet arrive dans `forward`, le DNAT a déjà réécrit la destination : c'est pourquoi on n'y voit ni le 22 ni le 23.

On vérifie la syntaxe **avant** d'appliquer quoi que ce soit :

```bash
sudo nft -c -f /etc/nftables.conf
```

Cette commande ne doit absolument rien afficher. Si elle affiche quelque chose, c'est une erreur de syntaxe et le pare-feu actif n'a pas encore été touché. Seulement alors, on applique :

```bash
sudo nft -f /etc/nftables.conf
```

Et on vérifie ce qui a été chargé :

```bash
sudo nft list chain inet filter forward
```

Maintenant, **depuis ton ordinateur, pas depuis le VPS** et **avec le VPN d'administration connecté**, les cinq ports doivent répondre. Ce sont les mêmes commandes qu'au 3.7.7, mais avec le résultat inverse : là-bas, elles devaient donner un timeout, ici, elles doivent se connecter.

| Commande | Ce qui doit sortir |
|---|---|
| `nc -vz -w 3 [IP VPS] 22` | `Connection to [IP VPS] 22 port [tcp/ssh] succeeded!` |
| `nc -vz -w 3 [IP VPS] 23` | `Connection to [IP VPS] 23 port [tcp/telnet] succeeded!` |
| `nc -vz -w 3 [IP VPS 2] 135` | `Connection to [IP VPS 2] 135 port [tcp/epmap] succeeded!` |
| `nc -vz -w 3 [IP VPS 2] 445` | `nc: connect to [IP VPS 2] port 445 (tcp) timed out: Operation now in progress` |
| `nc -vz -w 3 [IP VPS 2] 1433` | `Connection to [IP VPS 2] 1433 port [tcp/ms-sql-s] succeeded!` |

Et sous Windows, les cinq d'un coup. Ils doivent tous sortir `ABIERTO` sauf le 445, pour la raison expliquée juste en dessous :

```powershell
$ip1 = '[IP VPS]'; $ip2 = '[IP VPS 2]'; foreach ($prueba in @(@($ip1,22),@($ip1,23),@($ip2,135),@($ip2,445),@($ip2,1433))) { $h,$puerto = $prueba; $t = New-Object Net.Sockets.TcpClient; $abierto = $t.ConnectAsync($h,$puerto).Wait(3000); "{0,-16} {1,-6} {2}" -f $h, $puerto, $(if ($abierto) { 'ABIERTO' } else { 'cerrado o filtrado' }); $t.Close() }
```

<b>Que le 445 échoue depuis ton ordinateur est attendu, et ce n'est pas la faute du VPS.</b> Le TCP/445 sortant est bloqué par presque tous les VPN et presque tous les FAI grand public depuis les vers SMB, donc le paquet meurt avant de quitter ton réseau. Qu'il dise `timed out` et non `connection refused`, c'est justement le signe : un refus est envoyé par la destination, un silence est avalé par quelqu'un en chemin.

Il reste à écarter l'autre cause, qui, elle, serait grave : que le fournisseur du VPS le bloque <b>en entrée</b>, car le 445 est l'endroit d'où Dionaea tire le plus d'échantillons. On demande à Dionaea qui est arrivé, et cela ne dépend pas de ton réseau :

```bash
sudo python3 -c "import sqlite3; d=sqlite3.connect('/var/lib/docker/volumes/dirtyland_dionaea-var/_data/lib/dionaea/dionaea.sqlite'); [print(f'  puerto {p:<6} {c:>6} conexiones   {i:>5} IPs distintas') for p,c,i in d.execute(\"SELECT local_port, COUNT(*), COUNT(DISTINCT remote_host) FROM connections WHERE connection_type='accept' GROUP BY local_port ORDER BY local_port\")]"
```

<pre>
  puerto 135         7 conexiones       2 IPs distintas
  puerto 445         7 conexiones       1 IPs distintas
  puerto 1433        8 conexiones       3 IPs distintas
</pre>

Si le 445 cumule des connexions, il est ouvert sur Internet et le blocage est seulement de ton côté. S'il reste à zéro alors que les deux autres augmentent, c'est le fournisseur qui le bloque et il faut lui écrire. Laisse passer quelques heures : juste après le démarrage, l'échantillon est très réduit.

Et il reste une dernière vérification, dont dépend tout le signalement. Après ces connexions depuis l'extérieur, l'IP enregistrée doit être la tienne, pas la passerelle de Docker :

```bash
sudo grep -o '"src_ip": *"[^"]*"' /var/lib/docker/volumes/dirtyland_cowrie-var/_data/log/cowrie/cowrie.json | sort | uniq -c | sort -rn | head
```

Le nœud de sortie de ton VPN doit apparaître. Si tout continue de sortir comme `172.20.0.1`, Docker masque l'origine et **rien ne sera jamais signalé à personne** : la barrière écarterait tous les attaquants parce que ce ne sont pas des adresses globales, sans la moindre erreur. Le reporter le signale dans le journal, mais il vaut mieux le voir ici.

### 3.8.3 Passer le signalement en mode réel.

> [!IMPORTANT]
> **ICI, ON SIGNALE POUR DE VRAI.** Tout ce qui précède était de la simulation : le reporter lisait, décidait et écrivait dans le journal ce qu'il *aurait* envoyé, <b>sans rien publier</b>. La seule chose qui sortait sur le réseau, c'étaient des requêtes de lecture, car sans elles on ne pourrait pas valider les portes de décision, qui sont justement ce qu'on veut observer ces jours-là. Ici, on lui retire le frein, et à partir de la première passe du cron <b>on publie</b> sur les cinq plateformes.
>
> **CE QUI EST PUBLIÉ EST PUBLIC ET PERMANENT, ET NE PEUT PAS ÊTRE RETIRÉ.** Un commentaire sur VirusTotal ou un signalement sur AbuseIPDB, des gens vont les lire, et ils accusent une IP qui appartient à quelqu'un. C'est pourquoi l'ordre compte : on lit d'abord quelques jours de simulation, et seulement quand le résultat convainc, on change la ligne du cron.

Le cron reste en simulation, et il doit le rester quelques jours. L'endroit où regarder, c'est le journal :

```bash
sudo tail -n 60 /var/log/dirtyland-reporter/reporter.log
```

Ou `tail -f` si tu préfères le voir en direct, en te rappelant que celui-ci reste ouvert jusqu'à ce que tu appuies sur `Ctrl+C`.

Ce que l'on cherche là, c'est que ce qui *aurait* été envoyé soit raisonnable : des IP de vrais attaquants, aucune des nôtres, et les échantillons en attente de verdict au lieu d'être publiés à chaud. Et les refus, avec leur motif :

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --show-rejections 30
```

Quand le résultat convainc, et pas avant, on change la ligne du cron. C'est la même commande que celle de la section 3.5.8, et on l'utilise plutôt qu'un éditeur pour la même raison : à la main, on laisse les **deux** lignes actives ou **aucune**.

```bash
sudo sed -i -E 's|^(\*/15 .*malware-watch\.sh)$|#\1|; s|^#(\*/15 .*malware-watch\.sh --live)$|\1|' /etc/cron.d/dirtyland-reporter
```

Et on confirme qu'il reste **une seule** ligne active, avec `--live` :

```bash
grep -vE '^\s*(#|$)' /etc/cron.d/dirtyland-reporter | grep malware-watch
```

<pre>
*/15 * * * * root /opt/dirtyland/platform-reporter/malware-watch.sh --live
</pre>

> [!CAUTION]
> C'est l'étape qui commence à publier, et c'est le risque dont parle le 3.5.8.

## 3.9 Fin.

Une fois le honeypot déployé, après avoir attendu le temps que nous voulions attendre, et avec une bonne récolte de trouvailles, qu'il s'agisse de binaires, d'IP ou d'autre chose, c'est le moment de documenter ce que l'on a obtenu.

Heureusement, ce sont 3 scripts qui vont nous aider.

### 3.9.1 Analisis.py

Ce script :
- Extrait toutes les trouvailles de toutes les IP.
- Génère un rapport `.html` très détaillé et soigné, qui nous aidera à analyser ce qui s'est passé dans le honeypot.

Pour l'utiliser :

```bash
mkdir -p ~/datos-analisis && ln -sfn /var/lib/docker/volumes/dirtyland_cowrie-var /var/lib/docker/volumes/dirtyland_dionaea-var /var/lib/dirtyland-reporter "/opt/dirtyland/Telegram Reports/state" /opt/dirtyland/monitor ~/datos-analisis/ && sudo python3 /tmp/dirtyland-repo/ANALISIS/analisis.py --respaldo ~/datos-analisis --salida ~/analisis-senuelo-$(date +%F).html --ip-vps $(hostname -I) && sudo chown $USER: ~/analisis-senuelo-*.html
```

Pour récupérer les trouvailles chiffrées depuis la machine VPS. Le mot de passe est 1234, et rappelons que nous les chiffrons pour que Windows Defender ne se déclenche pas.

```bash
scp "dirtyland:~/dirtyland-respaldo-*.tar.gz.enc" .
```

Pour récupérer le rapport généré, qui se trouve sur la machine VPS.

```bash
scp "dirtyland:~/analisis-senuelo-*.html" .
```

### 3.9.2 Une seule IP

Ce script a été conçu avec l'idée de :
- Prendre les trouvailles d'une seule IP.
- Avoir le meilleur détail possible, pour une seule IP, sur ce qu'elle a fait ou non.
- L'analyse qu'il génère est un .txt qui inclut toutes les commandes qu'elle a exécutées, donc tu peux prendre tout ça, le coller à Claude et, s'il y a une commande que ce honeypot ne gère pas, la lui passer et laisser Claude travailler.

Voici comment le lancer :

```bash
sudo ~/que_hizo_esta_ip.py <IP>
```

Nous n'allons pas expliquer comment il fonctionne, car le script détaille déjà très bien comment l'utiliser.

Pour récupérer la trouvaille depuis la machine.<br>
<b>Sous Linux :</b>

```bash
scp 'dirtyland:~/ficha-*' "$(xdg-user-dir DESKTOP)"
```

<b>Sous Windows :</b>

```powershell
scp "dirtyland:~/ficha-*" ([Environment]::GetFolderPath('Desktop'))
```

Et nous l'aurons sur le bureau.

### 3.9.3 celui pour sortir les choses.

Ce script se contente de sortir les trouvailles, et c'est tout.<br>
Pour l'utiliser :

```bash
bash ~/respaldo.sh
```

Pour récupérer la trouvaille depuis la machine.<br>
<b>Sous Linux :</b>

```bash
scp 'dirtyland:~/dirtyland-respaldo-*.tar.gz.enc' "$(xdg-user-dir DESKTOP)"
```

<b>Sous Windows :</b>

```powershell
scp "dirtyland:~/dirtyland-respaldo-*.tar.gz.enc" ([Environment]::GetFolderPath('Desktop'))
```
