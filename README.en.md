> [!WARNING]
> **This is an AI made translation by Claude.** The original README is nearly five thousand lines and translating it by hand is not realistic. The canonical version, and the only one I wrote, is the Spanish one: [README.md](README.md).

[🇪🇸 Español](README.md) · **🇬🇧 English** · [🇧🇬 Български](README.bg.md) · [🇫🇷 Français](README.fr.md) · [🇩🇪 Deutsch](README.de.md)

# 1. Introduction

## 1.1 Purpose

Dear reader, I want to tell you, in a direct, personal and brief way, what the purpose of this project is.

The project is long enough already without even something as simple and personal as this taking me a long time to explain.

This project stems from two purposes:

- **On the one hand, a technical and professional one:** to design, deploy and operate a honeypot infrastructure capable of attracting, capturing and studying the activity of real attackers, applying rigorous criteria of design, security and containment. The infrastructure itself is something I am passionate about.

- **On the other, a personal purpose:** to serve as a calling card for my skills in the area of defensive cybersecurity, at a time when I am seeking professional development in this field.

Unlike a lab exercise, **this work faces real threats** and I am fully aware of the rigour, knowledge and philosophy that have to be poured into it, because I have a lot at stake; there can be no "human errors" here, and that is also the idea:

- **To demonstrate** my **ability** to do something from start to finish, meeting **a rigorous standard, with no human errors**; in defence, errors are not acceptable.

Likewise, exposing a machine to the internet in a controlled way and observing who tries to attack it, with what tools and with what goals, **offers a direct perspective on the real threat landscape that cannot be obtained in simulated environments, along with the stress, the pressure and the responsibility that come with it.**

That real-world nature is, for me, what gives the project its value and meaning. Beyond the technical exercise, the work is framed by an underlying motivation: **to contribute, even if modestly, to the defence against cybercrime**. Capturing malware and attack indicators, and reporting them to the competent platforms and authorities (where necessary), is not just a learning exercise but **a real contribution, however small, to the collective defence effort** made by analysts and security teams all over the world.

As for aspirations, the project aimed very high. Although I know full well that most of the captured activity will be automated, opportunistic traffic, it was designed with the ambition of being able to detect and document more significant threats (APTs).

**Aiming as high as possible while realistically accepting what is likely** is part of the approach with which it has been tackled.

Overall, this project aims to demonstrate practical skills in **secure infrastructure deployment, systems and network administration, and defensive cybersecurity and threat intelligence**, while also reflecting the genuine interest and vocation with which it has been carried out.

<p align="center">I hope you value, understand and above all enjoy every word/action carried out, as much as I have enjoyed it. Thank you.</p>

## 1.2 Scope

The aim of this project is the design, deployment and operation of a honeypot infrastructure geared towards capturing and studying the activity of real attackers on the internet. Specifically, the scope of the work includes:

- The deployment of **two complementary honeypots, Cowrie (for SSH and Telnet) and Dionaea (for multiple network protocols)**, on a virtual private server (VPS), using Docker containers.
- The design and implementation of the **security and containment measures** needed to expose the machine responsibly:
  - Firewall configuration with nftables.
  - Strict control of outbound traffic (egress).
  - Hardening of the containers.
- The customisation of the honeypots to make them more credible to attackers.
- The collection, observation and analysis of the captured activity (access attempts, commands executed and malware dropped).
- The reporting of the indicators obtained to threat intelligence platforms.

The following are **explicitly outside the scope** of this work:

- **Any offensive use of the infrastructure.** The project is strictly defensive and observational.
- **The attribution of the attacks** to specific actors, groups or countries, in keeping with the neutrality approach set out in the section on ethical considerations.
- **Exhaustive forensic analysis or in-depth reverse engineering** of the captured malware, which goes beyond the objectives of this project and could become a future line of work.
- **An enterprise-grade or production deployment.** This is an academic and portfolio project, albeit designed with professional criteria of rigour and security.

## 1.3 Audience

This work **is not aimed at beginners**.

It assumes a prior technical foundation, so it is intended for people with an **intermediate or advanced** profile:

- Recent graduates in computer or telecommunications engineering
- Master's students
- Professionals and experts in the field of cybersecurity.

It may also be of interest to:

- Security analysts
- Intelligence personnel
- Members of law enforcement agencies with cybersecurity responsibilities.

Throughout the document, the reader is assumed to be familiar with basic concepts of networking, Linux-based operating systems and server administration. Although many of these concepts are explained in detail throughout the project (for teaching purposes), it does not start from an absolute beginner level.

## 1.4 Ethical and legal notice

This **project falls strictly within** the field of **defensive cybersecurity research**. Its **purpose** is exclusively **the study of the techniques, tools and behaviours used by attackers**, with the aim of better understanding the threats and learning to defend against them. **Under no circumstances is the aim to attack, harm or retaliate against anyone.**

### Considerations on data and privacy

During the operation of the honeypot, data generated by the attackers themselves is collected, including source IP addresses.

It is worth remembering that **an IP** address **can be considered personal data for the purposes of**:

- The European Union's General Data Protection Regulation (**GDPR**).
- Organic Law 3/2018 on the Protection of Personal Data and Guarantee of Digital Rights (**LOPDGDD**), which implements it in Spain.

Along these lines, the Court of Justice of the European Union, in its judgment in the Breyer case (Case C-582/14, of 19 October 2016), held that **a dynamic IP address can constitute personal data** when there is a reasonable possibility of linking it to an identifiable person. Although the judgment was handed down under Directive 95/46/EC, which predates the GDPR, its reasoning is consistent with the one set out in Recital 26 of the current regulation.

Data protection rules **protect any natural person, including those who carry out unlawful activities**. The GDPR does not protect legal persons, such as companies.

Nor would it be correct to rely on the exemption for purely personal or household activities (Article 2(2)(c) GDPR) on the grounds that this is an individual project. The Court of Justice interprets that exemption restrictively: in the Ryneš case (Case C-212/13) it held that even a camera installed in a home that recorded part of the public road fell outside it. **A server exposed to the internet, whose data is moreover shared with public platforms, falls all the more clearly within the scope of the regulation.**

The processing of this data within this project is based on **legitimate interest (Article 6(1)(f) GDPR)**, aimed at ensuring network and information security, a purpose that the regulation itself expressly recognises as a legitimate interest in its Recital 49.

However, this processing is carried out in accordance with the principles of **minimisation and proportionality**: only what is necessary for the analysis of the threats is collected.

**As a precaution**, in this document **the following data has been anonymised or hidden:**

- IP addresses.
- Certain payloads.
- URLs and addresses of command and control (C2) servers.
- The project's own infrastructure data (the server's public IP, credentials and any data that could compromise its security).
- Other data about the attacker.

Although this data does not fall into the special categories that the GDPR considers sensitive (Article 9: health, ideology, ethnic origin, etc.), it was decided to anonymise it anyway.

The original analysis report, with the complete data, **is kept encrypted locally on my own computer for a maximum of one year** from the close of the project, after which it will be deleted. **It is not uploaded to GitHub or anywhere else on the internet** because there is no guarantee that what is published will be permanently erased:

- If someone downloads it first.
- The commit history.
- WayBackMachine

The decision to anonymise rather than pseudonymise was taken because **the GDPR only ceases to apply to truly anonymised data**, which by definition does not allow anyone to be identified, whereas **pseudonymised data is still personal data** because, with the right additional information, it can be traced back to the person.

And finally, regarding the "deletion within 1 year at most": as long as I keep the original report, I can undo the labels. Under a strict reading of Recital 26, which takes into account the means available to the controller itself, the published version would be anonymous to any reader but pseudonymised for me until I delete the original. There is legal debate as to whether this should be judged from the perspective of whoever receives the data or of anyone at all. But **deleting the original once the period expires settles that question under either interpretation.**

### Neutrality and geopolitical context

Throughout the project, the country associated with each IP address is shown **solely as technical data, never as attribution**. The IP addresses, as explained, have been anonymised for data protection reasons.

The country, on the other hand, is kept because on its own it does not identify anyone, but it should be interpreted with caution: **it is not possible to attribute an IP, a malware sample or any other data to a specific country with complete certainty.** The address that reaches the honeypot is only the last hop of the connection, and behind it there may be a proxy, a VPN, the Tor network, a VPS rented in a third country, a command and control (C2) server or, very often, a compromised IoT device that is part of a botnet and whose owner does not even know it is attacking.

On top of all this there are **false flags**, that is, traces left deliberately (language of the strings, time zones, reused infrastructure) to make the attack appear to come from somewhere else.

Even **the geolocation of an IP reflects where the address range is registered, not where the machine is located**, let alone the person who controls it. Moreover, as we will see later, IPv4 ranges are bought, sold and leased between organisations in different countries, so a block registered in one country may be operating in another, which muddles and complicates any attempt at geographical attribution even further.

**Therefore, the fact that a connection is associated with a given country does not mean that that country, or anyone living in it, is the author of the attack.**

There is also a contextual reason: given the current European geopolitical landscape, it was considered important for this work to remain on a technical and objective level, without making attributions or feeding any kind of dramatisation or exploitation of the situation. **The interest of the project lies in the technical "how" of the attacks, not in the "who"** or in their geographical origin.

### On the security of the system itself

It is worth being honest about a fundamental principle of the discipline: **there is no such thing as a 100% secure system**, and a honeypot, by its very nature as a deliberately exposed machine, accepts this from the outset.

What is possible, and this is the approach taken in this work, is to apply an **extremely rigorous, professional design with multiple layers of containment**, so that the risk is reduced to a known and controlled minimum.

### Provider authorisation and compliance with its terms

Before starting the project, the first step was to **request express authorisation from the company providing** the virtual private server (VPS).

To this end, an email was sent explaining, with full transparency, the nature of the project and the activities that were going to be carried out: the deployment of honeypots to capture and study the activity of real attackers. **The provider replied confirming that it agreed to the activity.** That email is not reproduced in this document for privacy reasons, but it is kept as a record that the activity was communicated and authorised in advance.

Likewise, the provider's policies and terms of use were reviewed one by one, in order to make sure that the operation of the honeypot stayed within the terms it sets.

**It is strongly recommended** that anyone wishing to replicate a project of this kind **ask their provider for authorisation beforehand and review its terms of use before deploying anything**. It is a simple step that avoids legal and service problems, and it is the responsible way to proceed.

## 1.5 Risks

Every honeypot carries an inherent risk: a machine is deliberately exposed to real attackers. The main danger is not so much that the attacker "wins" inside the emulation, but **that the compromised or abused machine becomes a tool for attacking third parties**, with all the traffic leaving from the project's public IP (with the resulting legal and reputational consequences and possible blacklisting). The risks identified and the measures taken for each one are detailed below.

### Risk 1: abuse of the wget and curl emulation for DDoS amplification (SSRF)

The most documented risk in Cowrie is the one described in vulnerability **CVE-2025-34469**. It is an SSRF (Server-Side Request Forgery) flaw in the emulation of the wget and curl commands: in emulated shell mode (the one used by default), these emulations make real HTTP requests to whatever destination the attacker specifies. With no rate limit on those requests, an unauthenticated attacker could invoke those commands repeatedly to generate unlimited HTTP traffic against a victim, **using the honeypot as a denial-of-service amplification node** and masking their own IP behind the honeypot's.

**How it is mitigated in this project:**

- The deployed version of Cowrie (3.0.10) is later than 2.9.0, which is the version that officially fixes this vulnerability. Therefore, **the deployment is not vulnerable to this specific CVE**.

- In addition, and independently of the patch, the outbound (egress) firewall imposes a strict rate limit on the containers' outgoing connections (see the egress section). This means that, even if a similar flaw existed, the machine could not generate the volume of traffic needed to amplify an attack. **It is defence in depth: it does not rely solely on the software being patched.**

### Risk 2: escape from the emulation to the real system

Although Cowrie simulates a fake file system and shell, it cannot be completely ruled out that some vulnerability might allow an attacker to escape the emulation and run code on the real system. **It is a low risk, but not zero.**

**How it is mitigated in this project:**

- Cowrie runs inside a **dedicated Docker container**, not directly on the host system.
- The **container is hardened** (no-new-privileges, limits on memory, CPU and number of processes), so any escape would run into a restricted environment.
- The outbound firewall **blocks access to internal networks and to the infrastructure itself**, preventing lateral movement (pivoting) even in the event of an escape.

### Risk 3: misuse of proxy mode (high interaction)

Cowrie has a high-interaction mode (proxy) that forwards SSH traffic to a real system. If it were enabled without any controls, it could be used to reach other systems.

**How it is mitigated in this project:**

- **The deployment uses emulated shell mode (backend = shell), not proxy mode.** This was verified in Cowrie's startup logs. There is no real system behind it to forward to.

### Risk 4: the attacker realising they are in a honeypot

An attacker who detects that they are facing a honeypot may leave, fake their behaviour or, in the worst case, retaliate. It is not a risk of harm to third parties, but **it does compromise the objective of the project (gathering intelligence)**.

**How it is mitigated in this project:**

- **Customisation of Cowrie** to make it more credible (hostname, system data consistent with a real Debian, plausible users and file system), detailed in the corresponding section.

And one last, very important thing **to mention about risk 4:**

**Objectively, it is almost impossible for the Cowrie and Dionaea machine not to look like a honeypot.**

Why?

1. They are medium- and low-interaction honeypots respectively; they have no hard drives or any persistent storage, so if you log in and create a file, it is deleted when you leave.

   And that gives it away.

2. There are scripts, control structures or uses of "python3" that are genuinely impossible to recreate.

   And that gives it away.

3. Commands that can break the simulation. Downloads of programs such as "nmap" or "masscan", or, something less common, updates or updating the machine. Is it really realistic to program it so that any program at all can be downloaded?

   And that gives it away.

**With just these 3 reasons, I hope you understand that it is almost impossible to recreate something 100% realistic.** The solution to this, which we are not going to use, is a high-interaction honeypot, a real machine.

# 2. Architecture, infrastructure and concepts.

The detailed explanations are in the main document. This repository
covers section 3, Procedures.

## 2.1 Architecture

![Architecture](IMG/arquitectura.png)

## 2.2 Infrastructure

|  | VPS |
| ---: | :---   |
| CPU | 1 core |
| RAM | 2GB  |
| STORAGE | 40GB (NVME) |
| IP(s) | 2 |
| BANDWIDTH | 4TB/month |
| OS | Debian 13, Trixie |
| HoneyPot | Cowrie + Dionaea |

# 3 Procedures

We will follow not just a logical order, but one of priority by importance. The procedure would be the same for almost any machine from almost any provider.

## 3.1 The only thing that is NOT copy and paste.

This guide is written so you can copy and paste commands without thinking too hard. <br>It includes explanations where they are needed, and there are moments where you will have to supply things: your IPs, your ports, your keys.

These are the nine files you will have to touch later on:

| File | Section | Why it cannot be copied |
|---|---|---|
| `/etc/hosts` | 3.2.1 | It contains the machine's hostname |
| `/etc/netplan/50-cloud-init.yaml` | 3.2.7 | It contains the second public IP |
| `/etc/ssh/sshd_config.d/99-hardening.conf` | 3.2.5, 3.2.6 | Administration port and permitted user |
| `/etc/nftables.conf` (parts 1 and 2) | 3.3 | They are applied **before** uploading the repository: at that point there is nothing to copy from |
| `/etc/nftables.conf` (parts 3 and 4) | 3.3.2, 3.8.2 | They could be copied; they are pasted on purpose, because the firewall is reviewed line by line and pasting it forces you to look at it |
| `/opt/dirtyland/docker-compose.yml` | 3.4 | It contains your two public IPs in the `ports:` |
| `/opt/dirtyland/cowrie/etc/cowrie.cfg` and `userdb.txt` | 3.4 | The decoy's cover story and passwords |
| `/opt/dirtyland/Telegram Reports/telegram.cfg` | 3.4.2.7 | Your two bot tokens and your chat |
| `/opt/dirtyland/platform-reporter/config.ini` | 3.5.5.1, 3.8.1 | The API keys for the five platforms |

Throughout the guide you will see `[IP VPS]`, which is Cowrie's, and `[IP VPS 2]`, which is Dionaea's. Everything else is pasted as it is.

## 3.2 After renting the VPS (after paying)

### 3.2.1 Do this immediately.

Access to the VPS is over SSH.<br>
When we make the purchase, it will ask us to supply the public key we generate on our local machine. It is important that the private key has a passphrase.

In my case, on Linux Mint:

```bash
ssh-keygen -t ed25519 -C "admin-honeypot"
```

We print the public key, paste it into the VPS provider's page and confirm.

```bash
cat ~/.ssh/honeypot_vps.pub
```

Thanks to this we can now reach the machine.

> [!IMPORTANT]
> If we delete the private key we hold locally, we lose access; so if we ever wanted to change it, we would have to create another private key first and remove the old one afterwards.

```bash
ssh -i ~/.ssh/honeypot_vps root@[IP]
```

Change the password of the user they gave us, whether it is "root", "admin" or whatever. In fact they should have sent us an email warning that the password must be changed as soon as possible.

Once we are inside over SSH:

```bash
passwd
```

This step is the most urgent one, unlike the ones that follow. We can also take the chance now to change the hostname if it is needed:

```bash
sudo hostnamectl set-hostname hostname
```

```bash
sudo nano /etc/hosts
```
And inside, on the same `127.0.0.1` line, you put the "hostname" next to it.

**In my case it warns me that THAT alone will not work. If your case IS NOT like mine, skip this step and go on to 3.2.2. Otherwise, edit the file, but we are going to edit cloud-init's one too (the template); the warning is this:**

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

We reboot, or run `exec bash`, or open a new terminal:

```bash
hostnamectl && cat /etc/hosts
```

### 3.2.2 Checks on what we bought.

The VPS architecture provides <b>two public IPs on the same machine</b>:
- One for the Linux decoy (Cowrie, SSH/Telnet)
- and a separate one for the Windows decoy (Dionaea, SMB/RPC/MSSQL).

The reason for using two IP addresses is that it makes no sense for Windows and Linux to share one. If Dionaea simulated a Windows environment and another one based on Debian 13 on a single IP address, that would give the VPS away as a honeypot.

That is why, when ordering the VPS, we request (or add) a second public IP.

For each of the two IPs we check:

- That the server is geographically located where we asked for it.
- That the IP has a good reputation. If it does not, we ask for a refund.
  - For that we will search these sites:
    - https://www.virustotal.com/gui/home/url
    - https://www.abuseipdb.com/
    - https://viz.greynoise.io/
    - https://www.shodan.io/
    - https://www.ipvoid.com/

- That there is no domain name associated with that IP (PTR record) left over from the previous owner. Out of hygiene and ethics towards whoever used that IP before.

![](IMG/Pasted%20image%2020261009175859.png)
![](IMG/Pasted%20image%2020261009175950.png)
- Check the ports and anything exposed on the VPS.

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

**Look at the Local Address column.** If it starts with `127.` or `[::1]`, the port only listens inside the machine and it does not matter what it is. What should worry you is anything listening on `0.0.0.0`, on `[::]` or on a public IP.

| Port | What it is | Exposed? |
|---|---|---|
| 53 on `127.0.0.53` and `.54` | systemd's DNS resolver | No, loopback |
| 25 | `exim4`, the local mail Debian ships with | No, loopback |
| 22 on `0.0.0.0` | Your SSH. The only thing open right now, and the one you are about to harden | Yes |
| 5355 on `0.0.0.0` | LLMNR, also from systemd-resolved | Yes, but the nftables `policy drop` covers it |

### 3.2.3 Prerequisites before hardening and configuring the host.

- Subscribe to Mullvad (in my case) and check that it works. What the firewall will let in over SSH is not "the VPN" but the **exit IPs of its SOCKS5 proxies**.
  If the VPN worked but the traffic did not go through the proxy, the machine would reject you (3.2.6.3).

> [!IMPORTANT]
> Never just one of those IPs: relays go down or get renumbered, and then your own firewall locks you out. Three of them go here, in different countries.

- And so as not to lose access to the machine, we need the VPS provider's website to offer a web console for configuring the machine from there, in case SSH access or anything else fails.

> [!TIP]
> Look at it **before** you need it. Many of them serve an old `noVNC` **with no clipboard**, and there you type everything by hand. Make the `root` password long, but typeable.

### 3.2.4 Principle of least privilege.

We will create a new user so as not to use root all the time, and so we do not log in over SSH as "root".
<p>We update the machine:</p>

```bash
apt update && apt upgrade -y
```

And we create a new user. The name does not matter at all, since nothing about the VPS will be exposed.

```bash
adduser --gecos "" user
```

We grant it "sudo" privileges:

```bash
usermod -aG sudo user
```
If sudo is not installed: `apt install sudo`.

```bash
groups user
```
And something like this has to come back:

`[NOMBRE USUARIO]: [NOMBRE USUARIO] sudo users`

### 3.2.5 SSH access for the new user.

> [!IMPORTANT]
> **Still as root:**

```bash
mkdir -p /home/user/.ssh
```
The keys I generated on my own computer to reach root will now be copied so they also give access to the new user:

```bash
cp /root/.ssh/authorized_keys /home/user/.ssh/authorized_keys
```

Since we are working as root, the files were created by "root", so we are going to change the owner to the new user and set the permissions SSH demands. The three go chained with `&&`, in a single paste:

```bash
chown -R user:user /home/user/.ssh/ && chmod 700 /home/user/.ssh && chmod 600 /home/user/.ssh/authorized_keys
```

> [!NOTE]
> <b>`&&` and not `;`.</b> With `&&` each command runs <b>only if the previous one finished cleanly</b>. If something fails, the chain stops dead and the error is visible.

If you want to check that everything is fine:

```bash
ls -lah /home/user/.ssh/
```
It will have to show:
- `drwx------` .
- `drwx------` ..
- `-rw-------` authorized_keys

And if you want to really check that it works, try connecting over SSH with the new user. Just in case, we open another terminal without closing this one and run:

```bash
ssh -i ~/.ssh/claveprivada user@[IP]
```

```bash
whoami && echo " " && groups && echo " " && id && echo " " && sudo whoami
```

It will show: <br>
`user` <br>
`user sudo user` <br>
`uid=1000(user) gid=1000(user) groups=1000(user),27(sudo),100(users)` <br>
`root`

### 3.2.6 Securing SSH.

In this new section:
- Open a new terminal, CTRL + SHIFT + T, whatever the operating system.
- We will decide which port other than 22 we will use to connect over SSH.
	- We want it not to be 22, so bots do not hammer it, because that is the one they aim at by default.
	- And not one of the obvious ones either: `2222`, `4444` or `4445` are scanned as heavily as 22 itself and save you nothing.
- Know the names of the proxy servers we will use in order to connect exclusively from those IPs over SSH and in no other way.

On the operational security approach, it is worth spelling out so the goal is not misunderstood:
- We are not after sophisticated OPSEC here, the kind where you pay for the VPN in cash by post so as to leave no financial trail. It is not needed, because that trail would only be visible to banks or governments, and this project's threat model is a far narrower one.
- What we want from Mullvad is one specific thing: that it hides the real IP by making the requests itself. What does need guarding properly is the Mullvad account number, because it works as username and password at once.

#### 3.2.6.1 If you are going to connect from Linux.

> [!IMPORTANT]
> **On our host machine, NOT THE VPS.**

As we said, we are going to connect through a SOCKS proxy, so the first thing we need to know is the IPs and the servers themselves.

Mullvad publishes the whole list through its API. This pulls the relays that have SOCKS5 **and are active**, with their country and city:

```bash
curl -s https://api.mullvad.net/www/relays/all/ | jq -r '.[] | select(.socks_name and .active) | [(.socks_name | sub("\\.relays\\.mullvad\\.net$";"")), .country_name, .city_name] | @tsv' | sort | awk -F'\t' '{printf "%-26s %-20s %s\n", $1, $2, $3}'
```

There are more than five hundred, so you will usually want to filter. The country goes in English, so Spain is `spain`:

```bash
curl -s https://api.mullvad.net/www/relays/all/ | jq -r '.[] | select(.socks_name and .active) | [(.socks_name | sub("\\.relays\\.mullvad\\.net$";"")), .country_name, .city_name] | @tsv' | grep -i spain | awk -F'\t' '{printf "%-26s %-20s %s\n", $1, $2, $3}'
```

If you do not have `jq`: `sudo apt install -y jq`.

**Pick three, in different countries:** one main and two backups. The name you need is the one on the left, without the `.relays.mullvad.net` suffix.

Now the file. The configuration is not written out here: it is in the repository, at **[Local SSH/For Linux/config](Local%20SSH/For%20Linux/config)**. Open it, copy the whole thing and paste it at the end of your `~/.ssh/config`.

Saving a copy of whatever was there first, and opening it to paste:

```bash
cp ~/.ssh/config ~/.ssh/config.bak 2>/dev/null; nano ~/.ssh/config
```

Once pasted, the placeholders between `< >` get replaced:

| Placeholder | With |
|---|---|
| `<IP a la que te vas a conectar>` | your VPS's public IP |
| `<Futuro puerto SSH>` | the port you will set in 3.2.6.3 |
| `<proxy principal>` | the relay you picked above, without the `.relays.mullvad.net` |
| `<proxy-respaldo-1>` and `<proxy-respaldo-2>` | the other two |
| `<pais-1>` and `<pais-2>` | whatever name you want to give the two backup aliases (`se`, `fr`, `jp`...) |

And it gets the permissions SSH demands:

```bash
chmod 600 ~/.ssh/config
```

**We check (optional)**. This reads the aliases you actually set from the file itself, so it works whatever you called them:

```bash
for h in $(awk '/^Host dirtyland/{print $2}' ~/.ssh/config); do
  echo "=== $h ==="
  ssh -G $h | grep -Ei '^(hostname|port|user|identityfile|proxycommand)'
done
```

#### 3.2.6.2 If your machine is Windows.

> [!IMPORTANT]
> **On our host machine, NOT THE VPS. If you did 3.2.6.1, do not do this one.**

Written on Windows 11 Pro.<br>
The OpenSSH client has shipped by default since Windows 10, reads the same `~/.ssh/config` and brings `ssh`, `scp` and `ssh-add`; nothing needs installing.

**1. Pick the three proxies.**

The same Mullvad list as on Linux, here with PowerShell. It prints the active SOCKS5 relays, sorted by country:

```powershell
(Invoke-RestMethod https://api.mullvad.net/www/relays/all/) | Where-Object { $_.socks_name -and $_.active } | Sort-Object country_name, city_name | Format-Table @{n='Proxy';e={$_.socks_name -replace '\.relays\.mullvad\.net$',''};width=26}, @{n='Pais';e={$_.country_name};width=20}, @{n='Ciudad';e={$_.city_name};width=22}
```

There are more than five hundred. To filter by country, add the filter:

```powershell
(Invoke-RestMethod https://api.mullvad.net/www/relays/all/) | Where-Object { $_.socks_name -and $_.active -and $_.country_name -eq 'Spain' } | Format-Table @{n='Proxy';e={$_.socks_name -replace '\.relays\.mullvad\.net$',''};width=26}, @{n='Ciudad';e={$_.city_name};width=22}
```
As we can see, it shows us the servers in Spain. If we wanted another country, we drop Spain and put the country in question in English.

**Pick three, in different countries:** one main and two backups. The name you need is the one in the `Proxy` column, without the `.relays.mullvad.net` suffix.

**2. Check that you have `connect.exe`.**

Linux's `ProxyCommand` uses `nc -X 5` to speak SOCKS5 with the relay, and Windows does not ship netcat. `connect.exe` replaces it, and it comes with **Git for Windows** (if you cloned this repository, you have it):

```powershell
Test-Path "C:\Program Files\Git\mingw64\bin\connect.exe"
```

It has to answer `True`. <br>
If it answers `False`, install Git for Windows and repeat the check:

```powershell
winget install --id Git.Git -e
```

**3. Create the `.ssh` folder and put the private key inside.**

```powershell
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.ssh" | Out-Null
```

Copy `honeypot_vps` in there (the file is the same one as on Linux, it copies across as it is) and check that it is where it belongs:

```powershell
Test-Path "$env:USERPROFILE\.ssh\honeypot_vps"
```

**4. Write the `%USERPROFILE%\.ssh\config` file.**

That is the file to edit. The configuration is not written out here: it is in the repository, at **[Local SSH/For Windows/config](Local%20SSH/For%20Windows/config)**. It is the same as the Linux one except for the `ProxyCommand` line, which calls `connect.exe` instead of netcat. Open it, copy the whole thing and paste it at the end of your `config`.

Saving a copy of whatever was there first, and opening it to paste (if it does not exist, Notepad will offer to create it):

```powershell
if (Test-Path "$env:USERPROFILE\.ssh\config") { Copy-Item "$env:USERPROFILE\.ssh\config" "$env:USERPROFILE\.ssh\config.bak" -Force }
notepad "$env:USERPROFILE\.ssh\config"
```

Once pasted, the placeholders between `< >` get replaced:

| Placeholder | With |
|---|---|
| `<IP a la que te vas a conectar>` | your VPS's public IP |
| `<Futuro puerto SSH>` | the port you will set in 3.2.6.3 |
| `<proxy principal>` | the relay you picked above, without the `.relays.mullvad.net` |
| `<proxy-respaldo-1>` and `<proxy-respaldo-2>` | the other two |
| `<pais-1>` and `<pais-2>` | whatever name you want to give the two backup aliases (`se`, `fr`, `jp`...) |

> [!IMPORTANT]
> **When saving, the file is called `config`, with no extension.** Notepad adds `.txt` on its own unless you choose "All files" in the type dropdown. Nothing reads a `config.txt`, and the symptom is that `ssh dirtyland` answers that it does not know that host.
>
> And under "Encoding", **UTF-8**, not "UTF-8 with BOM": those three invisible bytes at the start are enough to stop OpenSSH understanding the first line. The template is pure ASCII on purpose, which is why its comments carry no accents, so either of the two non-BOM options works.

**5. Private key permissions.**

On Windows the permissions are ACLs, not Unix bits, so there is no `chmod 600` here. OpenSSH refuses to use a private key that others can read, and without this it fails with `UNPROTECTED PRIVATE KEY FILE`:

```powershell
icacls "$env:USERPROFILE\.ssh\honeypot_vps" /inheritance:r /grant:r "$($env:USERNAME):(R)"
```

`/inheritance:r` cuts the permissions inherited from the folder, which is where the problem comes from, and `/grant:r` leaves only your user, with read access. Without the first one, the second fixes nothing: the inherited permissions are still there.

**6. Turn on the SSH agent.**

The key has a passphrase. On Linux the agent is already running; on Windows the service exists but **ships disabled**, so `ssh dirtyland` would ask you for it every time. In a PowerShell **as administrator**:

```powershell
Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent
```

If it answers `Acceso denegado`, that PowerShell was not an administrator one. Check before fighting with it, because it may already be done:

```powershell
Get-Service ssh-agent | Select-Object Name, Status, StartType
```

If it says `Running` and `Automatic`, the error did not matter: it was already as it should be.

And afterwards, in a normal PowerShell, the key gets added; the passphrase is typed here, just once:

```powershell
ssh-add "$env:USERPROFILE\.ssh\honeypot_vps"
```

**7. Check.**

This reads the aliases you actually set from the file itself, so it works whatever you called them. It does not connect to anything: it only shows what `ssh` has understood.

```powershell
$alias = Select-String -Path "$env:USERPROFILE\.ssh\config" -Pattern '^Host (dirtyland\S*)' | ForEach-Object { $_.Matches[0].Groups[1].Value } | Select-Object -Unique
foreach ($h in $alias) { "=== $h ==="; ssh -G $h | Select-String -Pattern '^(hostname|port|user|identityfile|proxycommand)' }
```

#### 3.2.6.3 Back to securing SSH.

> [!IMPORTANT]
> **INSIDE THE VPS, as the new user, NOT as root.**

The hardening goes in a file of its own inside `sshd_config.d/`, rather than editing the main `sshd_config`, for tidiness: it stays identified and easy to find instead of mixed in with whatever the provider's image brought.

```bash
sudo nano /etc/ssh/sshd_config.d/99-hardening.conf
```

It will be empty; we add:

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
The first SSH configuration, in short:
- We want to deny the possibility of logging in as root over SSH.
- Only the newly created "user" will be able to.
- Authenticating with a password is forbidden, private key only.
- Here the port is still 22 for connecting; we will change it later.

We check the syntax:

```bash
sudo sshd -t
```

```bash
sudo systemctl reload ssh
```

Once it has been applied after the restart, we are going to force access exclusively through Mullvad's SOCKS5 proxies. Therefore:
- We need to know the IPs we will use, 2 at minimum and 3 at most.
- Which SSH port we will connect through in future; in my case I settled on `56769`.

**And those IPs are not the ones Mullvad's API gives you.** `ipv4_addr_in` is the relay's **entry** address; the one your VPS will see arriving, and therefore the one to allow, is the **exit** address. You ask through the proxy itself, **from your machine and with the tunnel up**.

<b>On Linux:</b>

```bash
curl -sS -x socks5h://<proxy>.relays.mullvad.net:1080 https://am.i.mullvad.net/ip
```

<b>On Windows the same, with `curl.exe`:</b>

```bash
curl.exe -sS -x socks5h://<proxy>.relays.mullvad.net:1080 https://am.i.mullvad.net/ip
```

Once for each of the three proxies, changing the name. Those three addresses are the ones that go in the rules below. And look at them again if you ever lose access, because **Mullvad renumbers them**.

If instead of an IP you get `curl: (28) Connection timed out`, that relay is down. It is not your doing and waiting will not fix it: pick another and list them again, since the listing above only shows the ones that are active. The `-sS` is there precisely for this: it silences the progress meter but **not** the errors, because with a bare `-s` a downed relay prints nothing and it looks like nothing happened.

```bash
sudo apt install nftables -y
```

To check that it really installed:

```bash
sudo nft --version
```

And it will return something like: `nftables v1.1.3 (Commodore Bullmoose #4)`.

We wipe whatever content it had without deleting the file itself. It is very important not to delete it outright just because clearing it by hand in nano is tedious:

```bash
sudo truncate -s 0 /etc/nftables.conf
```

```bash
sudo nano /etc/nftables.conf
```

> [!IMPORTANT]
> And here we will use the contents of the file **[CORTAFUEGOS/nftables-PART-1.txt](CORTAFUEGOS/nftables-PART-1.txt)** from the repository. Mind the name: it has a hyphen before the number too.
> This is where we set both the new port we chose and SSH's port 22, so as not to drop the SSH session we currently have.

To check the file's syntax:

```bash
sudo nft -c -f /etc/nftables.conf
```

We apply it:

```bash
sudo nft -f /etc/nftables.conf
```

Now we edit the SSH file to add the new port (since we have already written the firewall rule that accepts only from IP X to port Y, which is the new SSH port):

```bash
sudo nano /etc/ssh/sshd_config.d/99-hardening.conf
```
It will end up like this:

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

`Port 22` has to be written out; leaving it implicit will not do: as soon as you declare any `Port` explicitly, SSH stops listening on 22 by default and serves only the ones you name. If you put only `Port 56769`, you would lose 22 the moment you reloaded.

We check the syntax:

```bash
sudo sshd -t
```

```bash
sudo systemctl reload ssh
```

The lowercase `-t` only says whether the file is written correctly. To see **what configuration actually ends up in force**, once the main `sshd_config`, whatever the provider brought and our own file have been combined, there is the uppercase `-T`, which dumps the final effective configuration:

```bash
sudo sshd -T | grep -Ei '^(port|permitrootlogin|pubkeyauthentication|passwordauthentication|allowusers|maxauthtries)'
```

If a directive does not show the value you just wrote, another file is overriding it.

We open another terminal, **without closing the previous one (CTRL + SHIFT + T)**, which is the lifeline: a session already started does not drop even if you change the configuration, because the changes only affect new connections, so that is the one you would revert from if something went wrong. With it open we try connecting with the VPN active, whichever server it is (and therefore on that new port we set):

> [!IMPORTANT]
> It is essential not to forget that we said the firewall rules mean ACCESS IS ONLY FROM MULLVAD'S PROXY IPs, which is to say that it does not matter whether you have the VPN active: if you try to reach the VPS over SSH it will not let you, because you will NOT be using the proxy's IP. To use the proxy's IP you have to run commands, and so on.
>
> And that is why we did the alias or shortcut at the beginning. And it does not matter which VPN server you connect to; it will always use the same proxies you gave it when you run that alias.

```bash
ssh dirtyland
```

It will work.

> [!TIP]
> It is therefore recommended to try all three aliases, one per proxy, and then to try getting in without going through any of them. That last one should NOT let us in.

```bash
ssh dirtyland-<pais-1>
```

```bash
ssh dirtyland-<pais-2>
```

Replacing `<pais-1>` and `<pais-2>` with the names you gave your two backup aliases. If you do not remember them, the file lists them: `grep '^Host dirtyland' ~/.ssh/config`.

> [!TIP]
> **If instead of getting in you get an error, the three suspects, in order:**
>
> - `Could not resolve hostname dirtyland` -> `ssh` cannot find the alias. On Windows the usual cause is the file being saved as `config.txt`; on both systems, it not being in your user's `.ssh` folder.
> - `UNPROTECTED PRIVATE KEY FILE` -> the private key's permissions. On Linux that is the `chmod 600`; on Windows, the `icacls` from section 3.2.6.2, which cuts the folder's inheritance.
> - `Permission denied (publickey)`, with `ssh -vv dirtyland` showing `Server accepts key: ...honeypot_vps` just before -> **it is neither the key nor the server**: the server says it accepts it. What happened is that `ssh` could not sign because it does not have the key's passphrase. It needs loading into the agent with `ssh-add` (or it is running without an interactive terminal, or with `BatchMode=yes`).

After this we edit the SSH file again and officially remove port 22, leaving only the port we wanted (56769):

```bash
sudo nano /etc/ssh/sshd_config.d/99-hardening.conf
```
We only remove port 22.
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

And that is that. <br>
We will probably wonder: <br><i>And what about the firewall rule for port 22?<br>
Does it have to go?</i><br>
No, we leave it; Cowrie will use it, and will then redirect 22 --> 2222.

Very important: we do a reload, because even though we have set the port and it genuinely will not let us in, internally that port is still taken. And later on it would stop us mounting Cowrie on 22.

This command DOES NOT DROP OUR CONNECTION, the way a `restart` would.

```bash
sudo systemctl reload ssh
```

We run a:

```bash
sudo ss -tlnp | grep -E ':(22|56769) '
```

To make sure it really has been released. It has to come out like this:

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

Also, and this is very important, we are going to try connecting over port 22 to see whether we really can no longer get into SSH through that particular port. From outside, on our own machine, we will try:

```bash
ssh -i ~/.ssh/honeypot_vps -p 22 user@[IP VPS]
```

`ssh: connect to host [IP VPS] port 22: Connection refused`
- `refused` means reachable but with no service. `timed out` means filtered.
- **Port 22, refused:** the firewall has `tcp dport 22 accept`, so the SYN packet crosses nftables and reaches the kernel. But in `ss -tulnp` there is nothing listening on 22: only 56769. Finding no associated process, the kernel answers with an RST, and your `nc` translates that as connection refused. That is to say, you got all the way to the end of the route and they told you nobody is there.
- **Ports 23 or a made-up one, timed out:** no rule accepts them, so they fall into `policy drop`. The packet is discarded without generating any answer at all, and your client sits waiting until the three seconds of `-w 3` run out.

### 3.2.7 Configuring the second IP.

As we established in the design (section 3.2.2), the machine has two public IPs: the main one (`[IP VPS]`) for Cowrie and a second one (`[IP VPS 2]`) for Dionaea. The provider assigns this second IP on an interface of its own (`ethX`), managed by cloud-init. After a reboot, the interface comes up configured automatically.

<b>(Optional)</b>

```bash
sudo reboot
```

On coming back, we check that the IP is present:

```bash
echo " " && hostname -I && echo " " && ip -br a
```

The only adjustment needed is removing the conflicting second default route that the new interface introduces. We edit the netplan and remove `ethX`'s `routes` block (leaving only its IP, with no default route of its own). The interface can sometimes be `eth2`, `eth1` or whatever. In my case there are three interfaces.

A backup, just in case.

```bash
sudo cp /etc/netplan/50-cloud-init.yaml /etc/netplan/50-cloud-init__$(date +%Y-%m-%d_%H:%M:%S).yaml.bak
```

We are not going to wipe its contents or anything, because it already has the IPs and MACs associated with it, everything is correct and we only want to remove one thing:

```bash
sudo nano /etc/netplan/50-cloud-init.yaml
```

Unlike other times, here we cannot simply copy and paste, because every time the machine is reinstalled or a new one is created, the MACs change. So importing what a previous instance or machine used (such as its MACs) makes no sense.

**You remove eth1's routes block.**

<pre>
      routes:
      - to: "default"
        via: "&lt;IP Gateway&gt;"
</pre>

It is worth mentioning that in MY case `eth2` corresponds to IPv6 and nothing else; my VPS simply does not put IPv4 and IPv6 on the same interface, it separates and isolates everything.

We verify the syntax:

```bash
sudo netplan generate
```

We apply it with a safety net (it reverts on its own after 20 seconds, in case we lose access):

```bash
sudo netplan try --timeout 20
```

If access holds, we confirm with ENTER and make it persistent:

```bash
sudo netplan apply
```

We verify that **a single** default route remains:

```bash
ip route show default
```

**Exactly one line** has to come out. If two come out, the `routes` block is still in place somewhere and you have to go back to `nano`.

And that the two public IPs are still there:

```bash
ip -4 -br addr show scope global
```

<pre>
eth0             UP             [IP VPS]/24
eth1             UP             [IP VPS 2]/24
</pre>

The command deliberately does not have the interface name written into it: here the second IP is on `eth1`, but on another machine it may be on `eth2`, and with the name hardcoded it would return nothing and it would look as if the IP had been lost when it is only called something else. This way it lists them **all** with their interface, and it checks both IPs and not just the second: if the missing one were the first, Cowrie would be left with nowhere to listen.

## 3.3 Docker + firewall.

We followed Docker's official guide for Debian (https://docs.docker.com/engine/install/debian/), with no substantial departures from the recommended procedure.
Prerequisites and removal of conflicting packages:

```bash
sudo apt update
```
```bash
sudo apt install -y ca-certificates curl
```
```bash
for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do sudo apt remove -y $pkg; done
```
There were no conflicting packages previously installed on the server, so this step removed nothing.

Adding Docker's official GPG key to APT's keyring, which APT needs in order to verify the authenticity of the packages:
```bash
sudo install -m 0755 -d /etc/apt/keyrings
```

```bash
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
```

```bash
sudo chmod a+r /etc/apt/keyrings/docker.asc
```

Declaring Docker's official repository: first failed attempt and the fix applied.
The official guide resolves the distribution codename and the architecture through command substitution inside a heredoc:
```bash
printf 'Types: deb\nURIs: https://download.docker.com/linux/debian\nSuites: trixie\nComponents: stable\nArchitectures: amd64\nSigned-By: /etc/apt/keyrings/docker.asc\n' | sudo tee /etc/apt/sources.list.d/docker.sources > /dev/null
```
  
Installing the engine and its components:

```bash
sudo apt update
```

```bash
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Verifying the installation:

```bash
sudo docker version
```

```bash
sudo systemctl status docker --no-pager
```

The version installed was Docker Engine 29.6.1, with the iptables backend over the iptables-nft compatibility layer (Experimental: false), which is the stable backend Docker recommended at the date of this deployment; the native nftables backend is still experimental in this version. The service came up active (`systemctl status docker` showed "active (running)").

The administrator user was not added to the `docker` group. Belonging to that group is, in practice, equivalent to having passwordless root access, since Docker has no verification mechanism comparable to sudo's. On a host meant to be exposed to real attackers, that trivial escalation path is not acceptable. Every Docker command is run with sudo.

### <u>3.3.1 DNAT theory and understanding the firewall rules (Optional).</u>

This section is theory and there is nothing to run.<br>
It explains why every rule that controls the decoys goes in the `forward` chain and not in `input`. <br>
If you are already clear on it, skip it.

**The problem.** Cowrie and Dionaea are containers, and a container has no public address. Docker hands them private addresses from its internal network, in our case `172.20.0.10` for Cowrie and `172.20.0.20` for Dionaea, with the host at `172.20.0.1` through the `dirtyland0` bridge (we use a bridge of our own rather than the stock `docker0`; that is all). Those addresses only exist inside the server. The only interfaces exposed to the internet are the host's `eth0` and `eth1` (_or even `eth2`, depending on your case_). So the question is how an attacker reaches the containers, and the answer is DNAT.

**But before that, what is NAT?** <br>
NAT (*Network Address Translation*) is not a protocol; it is a technique. A protocol defines how two parties talk: the format of the messages, the order, the meaning of each field, as IP, TCP or HTTP do. <br>
NAT defines no new message. What it does is rewrite the addresses in the headers of other protocols' packets as they pass through an intermediate device. It operates on IP addresses, which are layer 3, but when it also rewrites ports (the PAT or NAPT variant, which is exactly what happens when mapping a host port to a container) it touches layer 4 as well. The rigorous way to put it is that it acts on layer 3 and, often, on layer 4's ports.

Within NAT there are two variants, according to which address gets rewritten:

| | What it rewrites | Usual case |
|---|---|---|
| **SNAT** (*Source NAT*) | The **source** address | Going out to the internet: your private IP is translated to a public one so the destination knows where to answer. It is what the router at home does. |
| **DNAT** (*Destination NAT*) | The **destination** address | A packet arriving at a public IP is redirected to an internal machine. It is "opening a port", and it is exactly what Docker does when it publishes a container's port. |

What defines each one is which end it rewrites, regardless of the types of address involved.

**What decides the chain (input or forward)?** <br>
The existence of a DNAT does not by itself determine whether the traffic will go to `input` or to `forward`. What determines it is **the nature of the already rewritten destination**: if it belongs to the machine itself, it goes to `input`; if it belongs to another machine or to a container the host has to forward to, it goes to `forward`. Since the rewritten destination is the container, which as far as the network is concerned is another machine, the decoys' traffic **always** goes to `forward`.

That the packet physically passes through the host is irrelevant, because what counts for the firewall is who it is addressed to, not where it comes in. And the kernel decides that in a fixed sequence. The order is the key:

1. The packet comes in on `eth0` bound for `[IP VPS 2]:445`, our public IP.
2. **PREROUTING phase.** This is where the DNAT that Docker created when it published the port gets applied. The destination is rewritten and the packet is now bound for `172.20.0.20:445`, Dionaea's container. The translation happens **before** the kernel decides the route.
3. **Routing decision.** The kernel looks at the destination, which is already rewritten, and checks whether that IP is its own or another machine's. Since `172.20.0.20` is not the host's, it concludes the packet is to be forwarded.
4. Being a forwarded packet, it enters the `forward` chain. **It never touches `input`.**

As we can see, the `input` chain protects traffic addressed to the machine itself, such as the administration SSH on 56769, but **it does not see the containers' traffic**. That travels through `forward`. Which is why every rule controlling the decoys, both inbound towards them and outbound to the internet, is written in `forward`, the only point where the host, acting as a router, decides what it forwards and what it does not.

**Where to look, then.**

| To find out... | Look at | Is it yours |
|---|---|---|
| Whether the host is protected | `table inet filter`, `input` chain | Yes. That is where your SSH on 56769 is restricted to the proxies. |
| Whether the decoys are protected or exposed | `table inet filter`, `forward` chain | Yes. It is your real control point over Docker. |
| What Docker is doing underneath | `table ip nat` and `table ip filter` | No. The kernel itself warns you with the `do not touch`. You read them; you do not edit them. |

And the distinction between Docker's two tables: **`ip nat` translates addresses, `ip filter` decides whether the packet passes**.

In `table ip nat` lives the DNAT we have been talking about. Its `PREROUTING` chain is exactly the phase where the destination of incoming traffic gets rewritten. With the stack up and 445 published, that is where the rule translating your public IP to the container appears; with the stack stopped, the `DOCKER` chain is empty because nothing is published. This table neither blocks nor allows anything; it only translates. Its `POSTROUTING` does the inverse job, SNAT: the *masquerade* rule is the one that lets a container's `172.x` be rewritten to the public address when it talks outwards, so the answer knows how to come back.

In `table ip filter` is where Docker decides whether the already translated traffic passes, with its own `FORWARD` chain (distinct from yours) and its `DOCKER-USER`, `DOCKER-FORWARD` and other subchains. That one does allow or block, but remember what gets verified in 3.3.2: your `forward` in `inet filter` and Docker's `FORWARD` hang off the same kernel hook, and since a `drop` is final, **your `drop` overrides whatever Docker allows**. Which is why yours is the guardian and Docker's is secondary as far as you are concerned.

### 3.3.2 The firewall POST Docker.

First, a backup of the previous file:

```bash
sudo cp /etc/nftables.conf /etc/nftables__$(date +%Y-%m-%d_%H:%M:%S).conf.bak
```
We empty it again:
```bash
sudo truncate -s 0 /etc/nftables.conf
```

And **we put in part 2 of the firewall**, which is the content of **[CORTAFUEGOS/nftables-PART-2.txt](CORTAFUEGOS/nftables-PART-2.txt)** from the repository.

```bash
sudo nano /etc/nftables.conf 
```

Just as we did before, we simply put part 2 in.

**It is the same as part 1, but with a single change.** <br>
In part 1 the file started with `flush ruleset`. It did no harm, because Docker was not installed yet and there was nothing else to wipe. But now there is.

Docker has created its own tables (`ip nat`, `ip filter`, `ip6 nat` and `ip6 filter`), which coexist with ours (`inet filter`) without treading on each other because their families and names are different. But `flush ruleset` **does not just empty ours: it wipes everything**, Docker's included, and leaves the containers with neither address translation nor filtering until Docker recreates them.

That is why in part 2 that `flush ruleset` is replaced by two lines that reset only our table: `add table inet filter` and `delete table inet filter`.

The `add` creates the table if it does not exist, so that the `delete` that follows never fails by trying to remove something that is not there, and the `delete` removes it so it can be defined cleanly right afterwards. The effect is a reset of our table and of ours only.

Before applying it, make sure the syntax is right:

```bash
sudo nft -c -f /etc/nftables.conf
```

After writing the file, the commands that confirmed the fix works are:

```bash
sudo nft -f /etc/nftables.conf
```
```bash
sudo nft list tables
```
And the output it has to return:
- table ip nat
- table ip filter
- table ip6 nat
- table ip6 filter
- table inet filter

## 3.4 Cowrie + Dionaea.

> [!IMPORTANT]
> ### Panic button.
>
> To stop the docker compose:
>
> ```bash
> sudo docker compose -f /opt/dirtyland/docker-compose.yml down
> ```
>
> And to flush the `forward` chain, which is left denying everything because `flush` removes the rules but does not touch the policy:
>
> ```bash
> sudo nft flush chain inet filter forward
> ```
>
> They go from most to least forceful. After either of them, <b>check it, do not assume it</b>:
>
> ```bash
> sudo docker ps
> sudo ss -tulnp
> ```
>
> The first has to come back empty. In the second there can be nothing left of Cowrie or Dionaea: only internal loopback ports and services unrelated to the project.

<b>1. Preparing the folders</b>

The whole project lives under `/opt/dirtyland`. Instead of creating folders piecemeal throughout the document, we build **the complete tree in one go**: that way the starting point is always identical, the setup is reproducible, and no later section fails because a directory is missing.

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

The tree ends up like this:

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
    ├── tests/               # comprueban que las puertas saltan (3.5.5.2)
    └── cron.d/
</pre>

Outside `/opt`, two service paths are created for the reporters, paths that are not configuration but data: `/var/lib/dirtyland-reporter` (the state of what has already been reported, so as not to duplicate) and `/var/log/dirtyland-reporter` (its logs).

> [!IMPORTANT]
> Three of these names <b>cannot be changed</b>, because they are written inside the repository's scripts:
> - `/opt/dirtyland/Telegram Reports/` is used by the `telegram_alert_cowrie.py` plugin and by the ban service, and it is mounted into the container <b>at the exact same path</b> as on the host, so that the plugin's constant holds both inside and outside.
> - `/opt/dirtyland/monitor/` is where `daily-digest.sh`, `ssh-watch.sh` and `dionaea-watch.sh` look for `send-alert.sh` and `telegram.env`, by absolute path.
> - `/opt/dirtyland/platform-reporter/config.ini` is the reporter's default value, and `malware-watch.sh` and the cron file take that path for granted.

From here on, files from the repository are needed in several sections: the honeyfs `.tar`, the 70 command modules and their canned outputs, the `ps` output, Dionaea's `smb.yaml`, the volume generator and the reporter. They are all uploaded <b>in one go</b>, now, and the rest of the guide takes them from there.

On our machine, cloning the repository:

```bash
git clone https://github.com/iliangithub/Project_Dirtylands.git
```

Once the repo is downloaded, <b>the folder is not uploaded to the VPS as it is</b>; it is packed first with `git archive`, which pulls exactly what is committed and nothing else. This command packs, transfers, unpacks on the VPS and deletes the `.tar.gz` on both ends.

**On Linux:**

```bash
cd Project_Dirtylands && git archive --format=tar --prefix=dirtyland-repo/ HEAD | gzip > /tmp/dirtyland-repo.tar.gz && scp /tmp/dirtyland-repo.tar.gz dirtyland:/tmp/ && rm /tmp/dirtyland-repo.tar.gz && ssh dirtyland 'rm -rf /tmp/dirtyland-repo && tar -xzf /tmp/dirtyland-repo.tar.gz -C /tmp/ && rm /tmp/dirtyland-repo.tar.gz && echo subido'
```

**On Windows** that command will not do: PowerShell does not understand `&&`, there is no `/tmp` and it does not ship `gzip`. It is the same one as above using what it does understand (`;` to chain and `if` so as not to continue if something fails), and it also goes in a single paste:

```powershell
$repo = if (Test-Path .\Project_Dirtylands\.git) { ".\Project_Dirtylands" } else { "." }; git -C $repo archive --format=tar.gz --prefix=dirtyland-repo/ -o "$env:TEMP\dirtyland-repo.tar.gz" HEAD; if ($LASTEXITCODE -eq 0) { scp "$env:TEMP\dirtyland-repo.tar.gz" dirtyland:/tmp/ }; if ($LASTEXITCODE -eq 0) { ssh dirtyland "rm -rf /tmp/dirtyland-repo && tar -xzf /tmp/dirtyland-repo.tar.gz -C /tmp/ && rm /tmp/dirtyland-repo.tar.gz && echo subido"; Remove-Item "$env:TEMP\dirtyland-repo.tar.gz" }
```

It does not matter where you paste it from, next to the folder or already inside it.

Three differences from the Linux one:
- `git archive` compresses on its own with `--format=tar.gz` and writes with `-o`, so `gzip` is not needed
- the intermediate file goes to `%TEMP%` instead of `/tmp`, which does not exist on Windows
- and the `&&` that remain are the ones inside the quotes, which are run by the VPS's `bash`, not by PowerShell.

> [!CAUTION]
> <b>Why not an `scp -r` of the folder.</b> It copies the entire working directory and does not read the `.gitignore`, so it takes `.git/` and every `__pycache__` along with it. And the serious part: our `.gitignore` deliberately excludes `config.ini`, `telegram.env` and `*.sqlite3`, which are <b>the keys to the five platforms</b> and the reporter's state. If you have ever run the reporter on your own machine, those files exist in the local folder and an `scp -r` uploads them. Measured here: 1.6 MB with `git archive` against 11.4 MB with `scp -r`.

The transfers go through the <b>alias</b> in `~/.ssh/config`, which already carries the port, the user, the key and the `ProxyCommand`. Without it the firewall rejects the connection, because it only accepts the Mullvad proxy's IPs.

We check that it arrived complete:

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

If any `FALTA` comes out, the transfer was left half done: repeat the step above **and do not go on.**

The repository's scripts are always delivered with Unix line endings, even when downloaded from Windows, and a `.gitattributes` guarantees it. If you ever copy a script and it fails with `203/EXEC` under systemd or with `bad interpreter`, that file arrived with Windows endings: `sed -i 's/\r$//' fichero` fixes it.

```bash
cd /opt/dirtyland
```

```bash
sudo docker pull cowrie/cowrie:3.0.10
```

> [!CAUTION]
> <b>Cowrie's version is pinned, not on `latest`.</b> This setup replaces internal Cowrie files, the 70 modules from 3.4.2.8, and they depend on its internal API, which changes between versions without notice. It happened to us with `3.0.11`, which moved `cwd` from the protocol to the shell and turned `user` from an object into a dictionary: authentication worked, the MOTD came up and no prompt ever appeared. `3.0.10` is the last compatible one. Before moving up a version you have to check whether the API still fits:
>
> ```bash
> sudo docker run --rm --entrypoint /cowrie/cowrie-env/bin/python3 cowrie/cowrie:<version> -c "
> h=open('/cowrie/cowrie-git/src/cowrie/shell/honeypot.py').read()
> print('COMPATIBLE' if ('self.protocol.cwd' in h and 'self.user[' not in h) else 'API NUEVA: hay que adaptar los modulos')"
> ```

```bash
sudo docker pull cowrie/dionaea@sha256:7c3c1b7e3b0476f9ac17c4568979eb4d6c35c2f56ee1a5b6f3d835267babdc47
```

<b>Dionaea is pinned too</b>, and by digest rather than by tag, because the project only publishes `latest`. The reason is the same as with Cowrie: we replace its TDS module in step 5, and with `latest` a new image could bring that module changed and end up with our old copy mounted on top of it, without raising any error. To update it deliberately you redo the patch and change the digest, which you look up like this:

```bash
sudo docker image inspect cowrie/dionaea -f '{{index .RepoDigests 0}}'
```

<b>2. Configuring the Docker daemon</b>

```bash
printf '{\n  "userland-proxy": false,\n  "log-driver": "json-file",\n  "log-opts": { "max-size": "10m", "max-file": "3" }\n}\n' | sudo tee /etc/docker/daemon.json > /dev/null
```
```bash
sudo systemctl restart docker
```

<b>3. Cowrie's configuration files</b>
```bash
sudo nano /opt/dirtyland/cowrie/etc/cowrie.cfg
```
What we put inside was:
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

For this other file, the credentials one:

```bash
sudo nano /opt/dirtyland/cowrie/etc/userdb.txt
```
```
root:x:root
admin:x:admin
alyosha:x:alyosha123
user-ssh:x:987654321
```

The format is `usuario:x:contraseña`, one line per account and with none repeated. The `*` wildcard and the `!` negation are not used either: a `userdb` with `*:*:*` accepts any attempt and is one of the most immediate signs that there is a honeypot behind it.

The passwords are easy on purpose, and `root:root` most of all, because almost every attempt comes at `root`: if that account accepts none, the sweep bounces off without capturing anything. The price is the portrait of a badly administered machine, which is still credible. On the host it adds no risk, because there `root` over SSH is disabled and you only get in with a key from the proxies' IPs: this file describes the emulated decoy. `mihail` and `mykhailo` have a directory in `/home` and do not appear here, so they exist without anyone being able to authenticate as them.

> From experience, putting "admin" "admin" is all but mandatory, because the bots do not even bother with a dictionary attack where the brute force has to last more than 3 or 4 seconds. They go for whatever password is genuinely easiest. It does not matter if we take password number 1184 from the "rockyou.txt" password list; the bots simply are not going to put any effort into brute forcing.

The file is mounted read-only (`:ro`) into the container, so any change requires a `sudo docker restart dirtyland_cowrie` for Cowrie to read it again.

<b>4. Final docker-compose.yml</b>

```bash
sudo nano /opt/dirtyland/docker-compose.yml
```

The contents of this docker-compose are in **[DOCKER-COMPOSE/PART 1/docker-compose.yml](DOCKER-COMPOSE/PART%201/docker-compose.yml)**.

Remember to substitute these, which go in each decoy's `ports`:

- `[IP VPS]` -> the server's first IP, Cowrie's (ports 22 and 23).
- `[IP VPS 2]` -> the second one, Dionaea's (445, 135 and 1433).

And **as soon as you paste it**, check that the YAML is sound:

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml config >/dev/null && echo "compose OK"
```

It has to answer `compose OK`. If it does not, do not go on: the following steps mount volumes and bring up containers on top of this file.

Pasting YAML into `nano` is delicate, and that is why the check goes here and not three steps later: if a single line is lost or merged, `docker compose` fails with an error that does not say which line is wrong, of the `did not find expected key` sort.

> [!NOTE]
> <b>Only if the `config` above failed.</b> Do not hunt for the line by eye. Paste the whole file again. And if `nano` throws off the indentation when you paste, open it with auto-indent disabled:
>
> ```bash
> sudo nano -I /opt/dirtyland/docker-compose.yml
> ```
>

Each decoy is published bound to <b>its own</b> IP, not on every interface (`0.0.0.0`), so Cowrie only answers on its address and Dionaea on its own from the very first boot. Dionaea is exposed with three ports consistent with a Windows machine (SMB 445, RPC 135, MSSQL 1433) and its full customisation is in section 3.4.3.

<b>5. Dionaea's MSSQL patch</b>

It goes **before** bringing the stack up, and the order is not negotiable: the `docker-compose` mounts this file, and Docker, when the source of a file mount does not exist, **creates a directory with that name**. Dionaea would then start up unable to import its own module.

The reason is this. An `nmap -sV` against port 1433 of a stock Dionaea returns, with no scripts or anything:

<pre>
1433/tcp open  ms-sql-s  Dionaea honeypot MS-SQL server
</pre>

nmap carries that signature <b>in its built-in database</b>: it recognises Dionaea's TDS pre-login packet, which has the version hardcoded and announces a SQL Server 2000 (`8.0.528`). That is two problems on the same line: the decoy says its own name, and on top of that claims to be a version that does not fit the cover story.

There is no configuration key for that, so the file is pulled out of the image (the same technique as with `createfs.py` in 3.4.2.3) and the number changed:

```bash
cid=$(sudo docker create cowrie/dionaea@sha256:7c3c1b7e3b0476f9ac17c4568979eb4d6c35c2f56ee1a5b6f3d835267babdc47) && sudo docker cp "$cid:/opt/dionaea/lib/dionaea/python/dionaea/mssql/include/tds.py" /opt/dirtyland/dionaea/tds.py && sudo docker rm -f "$cid"
```

```bash
sudo sed -i 's/LEIntField("Version",268566536)/LEIntField("Version",1276654090)/' /opt/dirtyland/dionaea/tds.py
```

And **we check that the `sed` bit**, because if the image ever changed that line the `sed` would do nothing and say nothing:

```bash
grep -c 'LEIntField("Version",1276654090)' /opt/dirtyland/dionaea/tds.py
```

<pre>
1
</pre>

If `0` comes out, the image's file has changed: you have to look at what that field is called now before going on, not ignore it.

```bash
sudo chown root:root /opt/dirtyland/dionaea/tds.py && sudo chmod 644 /opt/dirtyland/dionaea/tds.py
```

`1276654090` is not a magic number: it is the four bytes `0a 32 18 4c` read little-endian, that is version **10.50 build 6220**, which is SQL Server 2008 R2 SP3, and that does fit a Windows 7. For another version, the bytes are `mayor, menor, build-en-2-bytes`.

<b>And a second file has to be taken out of the same module: without it, anyone can leave Dionaea hung by sending a single packet.</b>

This happened to me twice in one week and I had to make this emergency patch. <br>
Dionaea stopped recording connections and stayed that way for five days, and on restarting it, it hung again ninety seconds later, because the packet was sent again. <br>
Both times the last lines of its log were MSSQL ones. It does not crash; it sits there <b>spinning</b>, and that is why nobody notices: `docker ps` still says `Up`, the process exists and `nftables` keeps counting the packets coming in. All you can see is a core at 100% and a database that stops growing.

The bug is in `handle_io_in()`, and it is three consecutive lines:

<pre>
chunk = data[offset:offset+p.Length]
p = TDS_Header(chunk)      <b>&lt;-- se reescribe p con un trozo truncado</b>
offset += p.Length         <b>&lt;-- y se avanza con el Length del p NUEVO</b>
</pre>

The TDS header takes 8 bytes and its `Length` is the size of the whole packet, so it cannot be less than 8, yet only `0` is rejected. If someone declares <b>1, 2 or 3</b>, the chunk that gets sliced out is left without the bytes where the `Length` lives, the reparse fills them with zeros, `Length` comes out `0`, `offset += 0` and the loop goes back to the start with the same bytes. Forever, and without writing a line, because nothing gets logged down that path.

The fix is two lines and comes with the repository, with its whole explanation inside:

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
> <b>If you are UPDATING an installation that already works</b>, do not touch the `docker-compose.yml` by hand: a line has to go into a file that already has your IPs substituted in. From scratch it is not needed, because the compose gets pasted whole from `DOCKER-COMPOSE/PART 1`. This says what is missing without touching anything:
>
> ```bash
> sudo /opt/dirtyland/montajes-dionaea.sh
> ```
>
> And this puts it in, with the right indentation, leaving a backup and validating the YAML:
>
> ```bash
> sudo /opt/dirtyland/montajes-dionaea.sh --apply
> ```
>
> It can be run twice, and the list comes from the repository's compose, so a new mount is picked up automatically. If you do not have it installed yet (it gets copied in 3.4.2.9) it works just as well from `/tmp/dirtyland-repo/DOCKER-COMPOSE/montajes-dionaea.sh`. It exists because of a real failure: that line was pasted by hand and came out with the hyphen duplicated, and without that mount Dionaea hangs again on the first malformed MSSQL packet while the compose remains valid YAML.
>

> [!IMPORTANT]
> <b>The patch does not guess.</b> If the image's file is not exactly the one it expects, for instance after changing the `docker-compose` digest, it touches nothing, says `ESTE mssql.py NO ES EL ESPERADO` and exits with an error. A half-applied patch gets mounted on top without raising any failure, and that is worse. Running it twice breaks nothing: it says `ya estaba parcheado` and leaves.
>
> `test_parche_mssql.py` (section 3.7.10) does not check that the text changed: it <b>runs the loop</b> with a `Length = 1` packet, before and after, and verifies that the first never finishes and the second does.

The bug was not introduced by us: the `diff` of our `tds.py` against the image's is a single line, the version number one. What changed was what was sent to it, because somebody has to declare a `Length` of 1, 2 or 3, and the fact that the second hang arrived ninety seconds after a restart says that traffic is already continuous. With the patch, `nmap -sV` goes from `Dionaea honeypot MS-SQL server` to `ms-sql-s?`: it does not turn the port into a credible SQL Server under close analysis, but it stops announcing that there is a honeypot behind it.

<b>6. Bringing the stack up</b>

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml up -d
```
### 3.4.1 Improved firewall rules for the docker-compose.

```bash
sudo cp /etc/nftables.conf /etc/nftables_3.4.1.post.docker_creacion_compose___$(date +%Y-%m-%d_%H:%M:%S).conf.bak
```

The next firewall rule corresponds to the part 3 firewall rule, which again is in the repository's folder:

```bash
sudo truncate -s 0 /etc/nftables.conf
```

```bash
sudo nano /etc/nftables.conf
```

And we put in the contents of **[CORTAFUEGOS/nftables-PART-3.txt](CORTAFUEGOS/nftables-PART-3.txt)**. It matters that we review this one properly.

```bash
cat /etc/nftables.conf
```

Regarding the rules:
- In the input chain (not forward) there is the rule `tcp dport 22 accept`, which opens 22 to any IP. That rule was meant for the Cowrie decoy. But remember that traffic towards Cowrie's container goes through forward (because of the DNAT), not through input, so that input rule does not make the container reachable. The net result is still a timeout on 22, because forward blocks it. Seeing that `tcp dport 22 accept` line in input, you might think 22 ought to connect and no, it does not connect, because what decides for the container is forward, and forward discards it.

To check the file's syntax:

```bash
sudo nft -c -f /etc/nftables.conf
```

We apply it:

```bash
sudo nft -f /etc/nftables.conf
```

We are also going to see that the containers are still running:

```bash
sudo docker ps
```

Something like this should appear and show:

<pre>
CONTAINER ID   IMAGE                   COMMAND                  CREATED        STATUS        PORTS                                                                                                                                NAMES
7d5ee4b4cb4c   cowrie/cowrie:3.0.10    "/cowrie/cowrie-env/…"   20 hours ago   Up 20 hours   [IP VPS]:22->2222/tcp, [IP VPS]:23->2223/tcp                   dirtyland_cowrie
e7f37419a6af   cowrie/dionaea@sha256:7c3c1b…   "/opt/dionaea/entryp…"   26 hours ago   Up 26 hours   [IP VPS 2]:135->135/tcp, [IP VPS 2]:445->445/tcp, [IP VPS 2]:1433->1433/tcp           dirtyland_dionaea
</pre>

And yes, everything is sealed; it is still not exposed to the internet. To verify that this is true:

```bash
IP1=[IP VPS]; IP2=[IP VPS 2]; for par in "$IP1 22" "$IP1 23" "$IP2 135" "$IP2 445" "$IP2 1433"; do nc -vz -w 3 $par; done
```

Windows does not ship `nc`, so from PowerShell it is this instead (the `3000` is the same three seconds of waiting as `-w 3`):

```powershell
$ip1 = '[IP VPS]'; $ip2 = '[IP VPS 2]'; foreach ($prueba in @(@($ip1,22),@($ip1,23),@($ip2,135),@($ip2,445),@($ip2,1433))) { $h,$puerto = $prueba; $t = New-Object Net.Sockets.TcpClient; $abierto = $t.ConnectAsync($h,$puerto).Wait(3000); "{0,-16} {1,-6} {2}" -f $h, $puerto, $(if ($abierto) { 'ABIERTO' } else { 'cerrado o filtrado' }); $t.Close() }
```
<b>It has to give us an error!</b><br> 
`nc: connect to [IP VPS] port 22 (tcp) timed out: Operation now in progress`<br>
In PowerShell, the same thing said another way: `cerrado o filtrado` on all five.

> [!IMPORTANT]
> <b>Nothing is exposed yet</b>

#### 3.4.1.1 Why these rules: egress containment explained.

What follows explains the rules you have just applied, rule by rule.

A honeypot is, by definition, a machine deliberately left within reach of attackers. However well Cowrie and Dionaea emulate their services, you have to assume the worst: "that someone escapes the emulation and gets real code execution inside a container". In security you design for when things go wrong, not by trusting that they will not.

The danger in that scenario is not losing the machine; it is that **the machine becomes an attack platform against third parties**: mass scanning, denial of service, spam or propagation, all of it going out from the project's public IP and therefore with the legal and reputational consequences falling on whoever the VPS belongs to.

That is why egress control is the centrepiece of the containment, and with a principle behind it: the barrier is <b>not implemented inside the honeypot</b>, which is emulated software and which, if compromised, stops being under control, but underneath it, in the `forward` chain of the host's firewall, which still rules even if the container falls. The barrier that really contains is the hard one.

<b>The philosophy is permissive but controlled.</b> Blocking all egress guarantees zero harm to third parties, but it stops Cowrie completing the download of the payloads the attacker orders, and with it the samples are lost. We chose to allow the download while narrowing it to the minimum with surgical rules, because harvesting malware is one of the project's goals: allow only what a download needs and leave the machine useless for any mass abuse.

<b>The common anchor.</b> Every egress rule shares the same source condition: they apply only to traffic entering the routing stage from the containers' bridge (`iifname "dirtyland0"`) and whose source is their subnet (`ip saddr 172.20.0.0/24`). We do not filter all of the machine's outbound traffic, only the containers'; the host's own traffic leaves through its `output` chain, which accepts by default.

**Rule 1. Return traffic.** Connections that are already established or related (`established, related`) are accepted, and invalid ones are dropped. It is what lets replies to legitimate traffic flow. When a permitted download opens a connection, the return flow belongs to that connection and has to be able to pass. Dropping invalid traffic removes packets with an anomalous or corrupt state.

**Rule 2. Anti pivoting.** Six rules that stop a compromised container reaching destinations it has no business touching:

| Range | What it is | Why it is blocked |
|---|---|---|
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | RFC 1918 private addresses, not routable over the internet | Stops an attacker jumping into internal networks: the provider's, other customers' or the machine's own |
| `169.254.0.0/16` | *Link-local* or APIPA, what a machine assigns itself when it finds no DHCP | A container has no legitimate reason to head there |
| `100.64.0.0/10` | CGNAT, the block reserved for carriers' internal use | Closes another route towards the hosting provider's infrastructure |
| The server's own public IP | Ours | Stops the container turning on the host by attacking its services, for instance the administration SSH |

Their joint purpose is to close off lateral movement. Each block is logged with the prefix `DL-EGRESS-PRIV` or `DL-EGRESS-HOST`.

**Rule 3. Anti spam.** Outbound traffic to the mail ports is blocked: `25` (SMTP), `465` (SMTP over TLS) and `587` (authenticated submission). The machine cannot be used to send spam, one of the most common abuses of a compromised server.

**Rule 4. Anti amplification.** **All** outbound UDP from the containers is blocked. An amplification attack consists of sending small UDP requests with a forged source to reflector servers (DNS, NTP, memcached, SSDP), which answer with a far larger volume aimed at the impersonated victim. With no ability to emit UDP outwards, the machine cannot be the origin of that.

That a total UDP block does not break the decoy was verified explicitly. **The containers' DNS queries do not go out this way.** Docker's internal resolver (`127.0.0.11`) forwards to the host's resolver (`systemd-resolved`, at `127.0.0.53`), and it is the host that goes out to the internet to resolve, through its `output` chain, not the container through `forward`.

One accepted consequence: a payload served over <b>TFTP</b>, which runs on UDP, could not be downloaded. It was accepted because the vast majority are distributed over HTTP or HTTPS on TCP, and in exchange the amplification vector is closed with no exceptions.

**Rule 5. Outbound TCP with a rate limit.** It leans on one specific packet: the one carrying the SYN flag, which is what starts every new TCP connection. Filtering SYNs is equivalent to filtering attempts to open connections.

The first line allows new connections to be opened while limiting the rate to **10 per minute, with a burst allowance of 20**. Up to twenty openings almost back to back are tolerated and, from there on, a new one roughly every six seconds. The second drops and logs (`DL-EGRESS-RATE`) anything beyond that rate.

The underlying logic is an **asymmetry between legitimate use and abuse**. Downloading a payload is one or two connections and fits with room to spare. A port scan or a DDoS needs to open thousands per second and hits the limit immediately. The same rule permits the one and makes the other impossible.

The third line, accepting the rest of the TCP, is what makes the download work, because the limit only applies to <b>openings</b>: once the connection is admitted, its subsequent packets are no longer SYNs and the file comes down at normal speed. What is limited is how many new connections per minute the machine can open, not the throughput of an already authorised download. And any destination port is allowed, not just 80 or 443, because attackers host their payloads on non-standard ports and the rate limit already neutralises the abuse.

**Rule 6. Safety net.** Anything that has not matched any earlier rule is logged (`DL-EGRESS-OTHER`) and dropped. Together with the chain's default policy (`policy drop`), it guarantees that nothing unforeseen gets out. What is not explicitly permitted stays blocked.

<b>Logging as an alarm.</b> Every blocking rule leaves a record with an identifying prefix (`DL-EGRESS-PRIV`, `DL-EGRESS-HOST`, `DL-EGRESS-SMTP`, `DL-EGRESS-UDP`, `DL-EGRESS-RATE`, `DL-EGRESS-OTHER`). Under normal conditions the containers barely generate any blocked egress, so if attempts towards private networks, mail ports or at a high rate start appearing, the signal is that something inside a container is trying to escape the containment. The containment, as well as protecting, generates intelligence.

**Which threat each piece neutralises.**

| Abuse | Why it cannot |
|---|---|
| Serving as a reachable C2 | Inbound traffic is only forwarded to the decoys' ports; no new service is exposed |
| Amplifying | Outbound UDP is blocked |
| Scanning or joining a volumetric DDoS | Rate limit on new connections |
| Sending spam | SMTP is blocked |
| Pivoting | Blocked towards private networks and the provider's infrastructure |

The result is a machine capable of harvesting malware and useless as an attack platform.

**Verification.** The design was not taken as sound on paper alone. It was checked from inside a container (Dionaea):

1. That a permitted TCP download works. A request to an external web server on port 80 returned a `200`. In the same test it was confirmed that name resolution worked without any DNS rule in `forward`, exactly as anticipated.
2. That access to a private network is blocked. An attempt towards `10.0.0.1` was blocked and logged with `DL-EGRESS-PRIV`, showing source and destination.
3. That outbound UDP is blocked. Sending a UDP packet towards an external server was blocked and logged with `DL-EGRESS-UDP`.

<b>Honest scope.</b> No containment is absolute: this does not eliminate the risk; it reduces it to the minimum we consider acceptable. Even if someone escaped the emulation they could not send spam, amplify or pivot, because those vectors are closed off entirely; they could only scan or attempt a DDoS at a useless rate. The starting idea is to take it as given that you can be compromised, and to limit in advance what the machine can do outwards.

### 3.4.2 Customising and improving Cowrie.

In this section we extend the `docker-compose` to mount the fake directory tree, the custom configuration and the alerts. The compose grows in phases because each layer is verified before moving on to the next.

#### 3.4.2.1 Building the fake directory tree (honeyfs).

The directory tree the attacker will see inside Cowrie (the account of "Alyosha" and co., with their dotfiles, SSH keys, histories and the Node project) was designed and built separately, and we will not go into detail about how it was done. <br>

The point is to give the decoy a credible and coherent story. Building the content and its narrative design was done externally. Here we document how it is integrated into Cowrie.

<p>
But, to be brief, the files were simply created with Claude Code on a Debian 13 machine; the whole `home` is turned into an archived (not compressed) file and passed to the host machine. A compressed one would be something like a `.rar`; in our case, a `.tar` archive (which preserves modification times, something important for realism).
</p>

We recommend it be in `.tar` format and not `.rar`. Nor are we going to explain the adventure it would be if it were a `.rar`, or how to fix anything if it were a `.rar`.

`.tar` is used because it preserves the `mtime`s. A `.rar` created from Windows does not carry POSIX permissions or owners, so those metadata would have to be reconstructed separately.

The `.tar` is in the **COWRIE FAKE ENVIRONMENT** folder, so it already came with the repository in section 3.4 and all that is needed is to put it in place. <b>Mind the destination name</b>: it has to end up as `/tmp/home.tar`, not with the name it carries in the repository.

```bash
cp "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/honeyfs-home-DEFINITIVO.tar.gz" /tmp/home.tar
```

And we verify that it keeps the original `mtime`s. The designed dates (from 2026) should appear, not today's date:

```bash
tar -tvf /tmp/home.tar | head -5
```

> [!IMPORTANT]
> The name `/tmp/home.tar` is not a preference: it is the path that the filesystem generator (`build-dirtyland-fs.sh`, section 3.4.2.3) carries written inside it, in its `HOME_TAR` variable, and also the one extracted into the honeyfs in section 3.4.2.5. If it is uploaded under another name, the build does not find the tree and the decoy is generated with no `/home`. The extension does not matter: `tar` detects on its own that the file arrives compressed.

#### 3.4.2.2 The pickle problem and why it is regenerated whole.

Cowrie does not represent its virtual filesystem with real files, but with an index in "pickle" format (`fs.pickle`) that stores the metadata (name, type, uid, gid, size, permissions and date) of every path. The actual content of each file is served separately, from a "honeyfs" directory.

This has two key consequences:

- A file needs <b>both pieces</b> for the attacker to see it with content: an entry in the pickle (the metadata) and a real file in the honeyfs (the content).
    - If the pickle entry is missing, the file is invisible even though it is in the honeyfs.
- The pickle Cowrie ships with is a snapshot of an old Debian (12.5) and does not contain our users.
    - It cannot be "merged" with ours; it has to be <b>regenerated whole</b> from a real Debian system that includes both the system base and our tree.

Obviously, we do not produce those per-file metadata by hand. The tool that generates the pickle is `createfs.py`, which walks a real filesystem and records its metadata. It lives inside Cowrie's container, so first we confirm the container's real name (Docker Compose prefixes it with the project name):

```bash
sudo docker ps --format '{{.Names}}\t{{.Image}}'
```

And we extract the tool to use it in the generation:

```bash
sudo docker cp dirtyland_cowrie:/cowrie/cowrie-git/src/cowrie/scripts/createfs.py /tmp/createfs.py
```

Cowrie's image is minimal and does not ship `ls`, `find` or `grep`. To look inside you have to use `docker cp` or the Python from its own virtual environment (`/cowrie/cowrie-env/bin/python3`).

Two details from `createfs.py`'s code. The date field it stores in the pickle is the `mtime` and not the `ctime`, which is what we want: the dates designed into the tree survive intact. And <b>symbolic links are only preserved if their target falls inside the processed tree</b>; ours had none, but it is worth knowing in case one gets added.

#### 3.4.2.3 Generating the pickle from a real Debian 13.

<b>Why from a whole Debian and not by hand?</b> Because `createfs.py` invents nothing: it needs to <b>walk a real system</b> in order to photograph it. We fabricate what has to be fake, the story of our `/home`, and we copy what has to be real, the system with its ~69,000 paths and their exact permissions. A size that did not match Debian's real binary would be a tell.

The strategy is to bring up an ephemeral Debian 13 container (consistent with the version Cowrie announces), install the software the cover story requires, inject our `/home` tree on top, create the users with their fixed uids, normalise permissions and owners, and only then run `createfs.py`.

First we pull the base image:

```bash
sudo docker pull debian:13
```

The process is wrapped up in a script, which came with the repository in the **COWRIE FAKE ENVIRONMENT** folder. It gets copied and made executable:

```bash
sudo install -o root -g root -m 750 "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/build-dirtyland-fs.sh" /opt/dirtyland/
```

We run it:

```bash
sudo bash /opt/dirtyland/build-dirtyland-fs.sh
```

<b>On the VPS it runs with no resource limits, and that is on purpose.</b> The script accepts `LIMITES_CPU`, `LIMITES_CPUSET` and `LIMITES_MEM`, but they are empty by default: the VPS has a single processor, and pinning the container to other cores does not make the VPS slow; it leaves it unable to start at all (`Requested CPUs are not available`). Besides, this is where <b>the cover story's packages get installed</b>, so a small memory ceiling is not free either. Where the limits do help is when rehearsing on a desktop machine:

```bash
LIMITES_CPU=0.5 LIMITES_CPUSET=12-19 LIMITES_MEM=2g bash build-dirtyland-fs.sh
```

> [!TIP]
> <b>Rehearsing the regeneration off the VPS.</b> The script's five paths (`IMAGE`, `HOME_TAR`, `CREATEFS`, `OUT_DIR`, `HONEYFS_DIR`) default to the production ones, but they can be overridden through the environment and the whole chain run on another Debian machine with Docker before touching the decoy:
>
> ```bash
> SUDO="" OUT_DIR=/tmp/ensayo/fs HONEYFS_DIR=/tmp/ensayo/honeyfs \
>   HOME_TAR=/tmp/home.tar CREATEFS=/tmp/createfs.py \
>   bash build-dirtyland-fs.sh
> ```
>
> `SUDO=""` drops the `sudo` when the user is already in the `docker` group. Between rehearsals you have to delete the previous `fs.pickle.new`, because `createfs.py` refuses to overwrite its own output; the script checks for it at the start; otherwise the error only fires at the end, after installing every package.
>
> Two pieces are needed that are not in the repository. The `home.tar` does come with it; `createfs.py` is pulled from the exact image the `docker-compose` pins, not from GitHub, so that it is the same one running on the VPS:
>
> ```bash
> cid=$(docker create cowrie/cowrie:3.0.10)
> docker cp "$cid:/cowrie/cowrie-git/src/cowrie/scripts/createfs.py" /tmp/createfs.py
> docker rm -f "$cid"
> ```
>

The build container is launched with `--network host` because its package downloads, going out over Docker's default network, would fall into the firewall's `policy drop`. It is a one-off exception and only during the build.

> [!WARNING]
> The freshly generated pickle is **not yet trustworthy**. For some twenty system files (its internal `EMBED_PATHS` list: `/etc/hostname`, `/etc/hosts`, `/etc/resolv.conf`, `/proc/version`, `/proc/cpuinfo`, `/proc/meminfo`, `/proc/modules`) `createfs.py` does not record metadata; it embeds the content. And since that container runs with `--network host` on a virtualised VPS, they arrive with **the host's real data**: the server's hostname, references to `cloud-init`, a `resolv.conf` that says "Generated by Docker Engine", Docker's kernel modules, the `hypervisor` flag on the CPU and the real 2 GB of RAM. It has to be **sanitised** before installing it, and that is what the next section does.

#### 3.4.2.4 Verifying and sanitising the pickle before installing it.

The tree came out perfect, so the sanitising does not touch it: it rewrites only those twenty or so special files. The `/proc` ones because they are virtual and the kernel generates them on the fly, so that inside the container they describe the VPS's real hardware, and the network ones because with `--network host` they inherited the host's identity.

Cowrie ships a tool (`dumpfs.py`) for dumping the pickle as text and auditing it. We extract it and check that the users, uids, permissions and content are the right ones:

```bash
sudo docker cp dirtyland_cowrie:/cowrie/cowrie-git/src/cowrie/scripts/dumpfs.py /tmp/dumpfs.py
```

**We check that the five users come out with their correct uids and with the home at `40750`:**

The `40750` (`drwxr-x---`) is what stops one user poking around in another's home. With `40755` the decoy would let any account list the others' projects and keys, and the modules' permission checks would have nothing to deny. `build-dirtyland-fs.sh` sets it, because `useradd -m` creates the homes at `0755`.

```bash
sudo python3 /tmp/dumpfs.py /opt/dirtyland/cowrie/fs/fs.pickle.new | grep -E '^/home/(mihail|admin|user-ssh|mykhailo|alyosha)\s'
```
The output it has to give:

/home/admin	    DIR	40750	1001:1001	4096<br>
/home/alyosha	DIR	40750	1004:1004	4096<br>
/home/mihail	DIR	40750	1000:1000	4096<br>
/home/mykhailo	DIR	40750	1003:1003	4096<br>
/home/user-ssh	DIR	40750	1002:1002	4096<br>

**We check critical permissions (SSH keys at 600, .env at 600) and that the base is Debian 13:**

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

**We check that Docker's "tell" (`/.dockerenv`) was removed (it must come out empty):**

```bash
sudo python3 /tmp/dumpfs.py /opt/dirtyland/cowrie/fs/fs.pickle.new | grep -iE 'dockerenv'
```

It returns nothing.

The most important part is still missing, and it is not visible by looking at the tree: **what content `createfs.py` embedded inside the system files**. It came from the real host, and that is why it carries its data. In our case it gave away twelve things, all of them from having generated the pickle on a virtualised VPS and with `--network host`:

| File | What it gave away |
|---|---|
| `/etc/hostname`, `/etc/hosts` | The server's **real** hostname, and traces of `cloud-init` |
| `/etc/resolv.conf` | Literally `# Generated by Docker Engine`, and the provider's domain |
| `/proc/modules` | Docker's modules (`veth`, `bridge`, `br_netfilter`, `xt_MASQUERADE`): the fingerprint of a container host |
| `/proc/cpuinfo` | The `hypervisor` flag, the classic virtualisation giveaway, and a server-grade Xeon Gold with a single core |
| `/proc/meminfo` | The VPS's real 2 GB |
| `/proc/version` | A kernel with a `-cloud` suffix and a different build date. It contradicts `uname -a` |
| `/etc/os-release` | Empty, because it is a link to `/usr/lib/os-release`, which is not in `EMBED_PATHS`. And it is one of the first things anyone looks at |
| `/etc/localtime` | `Etc/UTC` instead of the cover story's zone. On Debian 13 that link **is** the time zone, because `/etc/timezone` no longer exists |
| `/etc/group` | The `sudo` group empty, with a `.bash_history` full of `sudo apt` |
| `/etc/shadow` | Every account locked and dated the day of the build, not in March as the cover story says |
| `/proc/mounts`, `/etc/mtab` | Links to the build container's PID, that is to say **broken**: `cat /etc/mtab` returned nothing |
| `/proc/9355`, `/proc/self` | A directory with the build's PID. An `ls /proc` shows two numbers and the second does not appear in `ps aux` |

Three more are fixed **outside the pickle**, in 3.4.2.8: `ps` showed another machine's processes, `netstat` gave away an Ubuntu and `free` reported the host's RAM.

The `/proc` files cannot be written by hand in the container, so the only way is to rewrite the bytes already embedded in the pickle. `sanitize-pickle.py` takes care of that, leaving them consistent with the cover story: a development PC with an i5-12400, 16 GB of RAM, a kernel without `-cloud`, corporate LAN DNS and `alyosha` in the sudo group. It writes them into the `honeyfs` too, because some emulated command, such as `free`, reads them from disk and not from the pickle.

The script is in **COWRIE FAKE ENVIRONMENT**, so it also comes with the repository:

```bash
cp "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/sanitize-pickle.py" /tmp/sanitize-pickle.py
```

And then it gets run. It takes the freshly generated pickle, writes the final sanitised pickle, and along the way populates the `honeyfs` with the files the emulated code reads from disk:

```bash
sudo python3 /tmp/sanitize-pickle.py /opt/dirtyland/cowrie/fs/fs.pickle.new /opt/dirtyland/cowrie/fs/fs.pickle /opt/dirtyland/cowrie/honeyfs
```

Note the order: `fs.pickle.new` goes in, the dirty one, and `fs.pickle` comes out, the definitive one. That way the `.new` is left as a backup of the unsanitised state.

The first thing it does is make `/proc/mounts` and `/etc/mtab` **readable**, and write the disk's story:

<pre>
Corrigiendo /etc/mtab y /proc/mounts:
  OK: /etc/mtab -> /proc/mounts
  OK: /proc/mounts pasa de enlace roto a fichero con la tabla
</pre>

<b>Why a single table.</b> `/proc/mounts`, `/etc/mtab` and the `mount` command say the same thing on a real Linux, so all three come from the script's `PROC_MOUNTS` constant. Keeping them separate is a guarantee that one day they will stop matching. The sizes are not free either: `/dev` is half the memory the canned `dmesg` announces, `/run` is 10% of `MemTotal` and `/dev/shm` 50%, which are the calculations the kernel and systemd make, so `df -h`, `mount` and `/proc/meminfo` add up on their own. And the disk is an NVMe because `/proc/modules` loads `nvme` and not `ahci`.

`/proc/mounts` ends up as a file rather than a link to `/proc/self/mounts`, and that is a conscious trade: an `ls -l` shows a file where a Debian shows a link, but in exchange `cat /proc/mounts` works.

And it removes the trace of the container that generated it:

<pre>
Quitando el PID del contenedor de construccion:
  OK: /proc/9355 renombrado a /proc/48230 (el bash de ps)
  OK: /proc/self -> /proc/48230
</pre>

The number is not chosen at random: **48230 is the `-bash` that `ps_command_output.json` declares**, so the PID that comes up in `ls /proc` is one of the ones `ps aux` recognises. The JSON's 85 processes are not cloned because each one would drag along its fifty-odd files under `/proc/<pid>/`.

Before that it fixes **the targets of every symbolic link**, which number several thousand:

<pre>
Corrigiendo los enlaces simbolicos:
  OK: 7453 destinos de enlace con su barra inicial
</pre>

<b>Why they have to be touched.</b> `createfs.py` stores the target with `os.path.realpath(path)[len(localroot):]`, and with `localroot="/"` that strips the leading slash. The result shows up in any `ls -l` on the decoy:

<pre>
localtime -> usr/share/zoneinfo/Europe/Kyiv
S01cron   -> etc/init.d/cron
</pre>

A real Linux prints `/usr/share/zoneinfo/Europe/Kyiv`, and it is not an isolated link: it affects every one in the filesystem. It also threw off the size, because a link's `st_size` is the length of the original target (`../init.d/cron`, 14) and what was stored is the resolved one (`etc/init.d/cron`, 15), so it gets recalculated. What cannot be recovered is the relative form, which `realpath` has already lost: what remains is an absolute link, valid and coherent even though a stock Debian has a relative one there.

And it warns if the package list that feeds `dpkg -l` is missing:

<pre>
Lista de paquetes para dpkg -l:
  OK: 558 paquetes, del mismo contenedor que el pickle
</pre>

There is nothing to copy anywhere: the `docker-compose` mounts it from `fs/`, which is where the generator leaves it, next to the pickle. **That is on purpose.** Copying it by hand would be one more step, and the day the filesystem got regenerated without repeating it, the decoy would be left with the new pickle and the old package list: two different versions of itself, with no error to say so. The artefacts that **are generated** all live in `fs/` and are mounted from there; in `etc/` there is only what comes written from the repository.

<b>Why `dpkg -l` does not carry its list inside.</b> It used to, a table of 26 packages written by hand, and it had aged without anything warning us: 20 of those 26 versions no longer matched Debian 13 and one contradicted the banner the decoy itself announces. Besides, 26 is few, since a freshly pulled `debian:13` already brings 78. Now the list comes from the same container that generates the pickle, so `dpkg -l` and the fake disk cannot disagree, and the module only formats it, reproducing the columns, which fit themselves to the content.

In between, it corrects the time zone, which on Debian 13 lives in a link and not in a file:

<pre>
Corrigiendo la zona horaria:
  OK: /etc/localtime -> usr/share/zoneinfo/Europe/Kyiv
</pre>

If an `AVISO: ... no esta en el pickle` comes out, the sanitiser **leaves the link as it was** instead of leaving it broken, pointing at a zone that does not exist in the tree: a broken link gives more away than a UTC. It would mean that `tzdata` did not make it into the build container.

The zone ends up stated in <b>three</b> places and all three have to match, because they cover different readers: the service's `TZ` variable and the `/etc/localtime` mount govern the container's processes, which is where the dates the decoy prints come from, and this link inside the pickle is what the attacker sees with an `ls -l /etc/localtime`. If the decoy answers with Kyiv time and its `/etc/localtime` says `Etc/UTC`, those are two halves of the same lie that do not hold together.

The sanitiser finishes with two more things, added when telnet was enabled:

**Coherence check.** It warns if the decoy would offer port 23 with nothing on its disk to explain it. There are **two** lines, and both are needed:

<pre>
Coherencia de telnet:
  OK: el pickle trae inetd, su configuracion y el servidor
  OK: /etc/inetd.conf declara telnet sin comentar
</pre>

If an `AVISO: faltan en el pickle: ...` comes out instead, the packages are missing: they have to be added to `PACKAGES` and the pickle regenerated. It does not abort, because a pickle without telnet still works for SSH, but it refuses to go unnoticed, which is precisely what is needed: the degradation would be invisible at boot.

<b>Why it is checked in two places.</b> The listing comes from the pickle, but the content of `/etc/inetd.conf` does not appear in `EMBED_PATHS`, so it arrives empty and what a `cat` answers comes from the honeyfs. Checking only the first half gave a <b>misleading OK</b>: `inetutils-telnetd` on trixie installs only the binary and registers nothing, so the file arrived fully commented out while the decoy answered on 23, and a `cat` showed a machine that does not explain its own open port.

The warning, if it fires, is `AVISO: /etc/inetd.conf NO declara telnet`. Debian itself activates the line inside the build container with `update-inetd --enable telnet`: it already comes in the file, disabled with the `#<off>#` marker.

**Installing the stock `/etc` files.** The sanitiser copies into the honeyfs whatever `build-dirtyland-fs.sh` exported into `fs/honeyfs-etc/`, and it does so in the same command so there is no manual step that can be forgotten:

<pre>
  OK: /opt/dirtyland/cowrie/honeyfs/etc/inetd.conf      (de Debian, no inventado)
  OK: /opt/dirtyland/cowrie/honeyfs/etc/issue           (de Debian, no inventado)
  OK: /opt/dirtyland/cowrie/honeyfs/etc/issue.net       (de Debian, no inventado)
  OK: /opt/dirtyland/cowrie/honeyfs/etc/ssh/sshd_config (de Debian, no inventado)
</pre>

<b>Two origins, and the difference matters.</b> The cover story's files (`hostname`, `hosts`, `resolv.conf` and `localtime`'s target) are <b>invented</b>, because they have to lie. The stock ones (`issue`, `issue.net`, `inetd.conf` and `ssh/sshd_config`) are <b>copied</b> from a real Debian, because they do not depend on our story and writing them by hand means inventing a format; in `sshd_config`, `PermitRootLogin yes` is changed before copying it, because the decoy accepts `root` with a password. And `etc/issue.net` is not decorative: it is where Cowrie takes the telnet banner from, and if it is missing, Cowrie writes `ERROR: Failed to load /etc/issue.net` at every boot and serves an empty banner.

We check that the banner came out right:

```bash
sudo cat /opt/dirtyland/cowrie/honeyfs/etc/issue.net
```

And that the pickle already carries the telnet server and its configuration:

```bash
sudo python3 /tmp/dumpfs.py /opt/dirtyland/cowrie/fs/fs.pickle | grep -E '^/(etc/inetd\.conf|usr/sbin/(inetd|tcpd|in\.telnetd|telnetd))\s'
```

It is not enough that they exist: you have to see what the attacker would see on opening the file. The telnet line has to come out **uncommented**, along with the two binaries it cites in the previous command:

```bash
sudo grep -vE '^\s*#|^\s*$' /opt/dirtyland/cowrie/honeyfs/etc/inetd.conf
```

<pre>
telnet	stream	tcp	nowait	root	/usr/sbin/tcpd	/usr/sbin/telnetd
</pre>

If that line comes out preceded by `#<off>#`, the file is as Debian leaves it out of the box and the `update-inetd --enable telnet` from 3.4.2.3 did not run.

This sanitises the <b>pickle</b>, but there is a <b>second part</b>: three commands Cowrie emulates (`ps`, `netstat`, `free`) also give away the real environment and need mounting as binds in the compose, so they get sanitised in section 3.4.2.8, once it is defined.

#### 3.4.2.5 Preparing the honeyfs (contents).

The honeyfs is the directory with the files' real content. It is extracted from the same tar, keeping the path.

<b>Why the same tree twice?</b> Because the pickle stores the <b>metadata</b> (what an `ls -la` sees) and the honeyfs the <b>content</b> (what a `cat` sees). Both come from the same tar so that sizes and content add up.

```bash
sudo tar -xpf /tmp/home.tar -C /opt/dirtyland/cowrie/honeyfs
```

We check that it landed where it belongs (the five users under `honeyfs/home/`) and that the dates are still the designed ones and not today's:

```bash
ls -la /opt/dirtyland/cowrie/honeyfs/home/
sudo find /opt/dirtyland/cowrie/honeyfs/home -newermt '30 days ago' | head
```

The first command must list `admin`, `alyosha`, `mihail`, `mykhailo` and `user-ssh`; the second must return nothing (if it returns files, the `.tar` was created or extracted losing the `mtime`s, and the whole tree would look freshly created).

`tar`'s `-p` preserves permissions, and extracting as root also preserves owners. It matters because the decoy's `.env` and SSH keys have to stay at `600`: a credentials file readable by everyone is as suspicious as not having one.

#### 3.4.2.7 Real-time alerting over Telegram (Cowrie).

This does not require touching the firewall: the container's DNS is resolved by Docker internally, without going out through `dirtyland0`, so the outbound UDP block does not affect it, and outbound TCP/443 was already permitted.

Cowrie itself ships a plugin for notifying over Telegram. We are going to modify it, though. By default it reports:

- `cowrie.login.success` -> somebody guessed a set of credentials and got in.
- `cowrie.command.input` -> a command Cowrie does know how to emulate.
- `cowrie.command.failed` -> a command Cowrie does **not** recognise. Careful, this does not mean "wrong command": these are the exotic binaries the attacker expected to find, and they usually give their intent away better than ordinary commands do.
- `cowrie.session.file_download` -> something was downloaded

And these are our five modifications on top of the original:

1. **A timestamp on every alert.** The original plugin did not include one; with several alerts arriving in a burst, knowing the time without going to the log matters.
2. **Enriched downloads.** As well as the URL, it now includes the **SHA256**, the destination file and a ready-built VirusTotal link for that hash. It is what feeds the report's reporting phase directly.
3. **An AbuseIPDB link** under each IP, so you can see country, ASN and reputation with one tap. It is done this way, rather than querying a geolocation API from the honeypot itself, so as not to generate extra outbound traffic competing with the egress rate limit, and not to add third-party dependencies: the lookup is made by the operator from their phone, not by the machine.
4. **It also reports `cowrie.session.file_upload`** (SCP uploads), which the original ignored. An upload is as interesting as a download.
5. **It escapes HTML in the attacker's input.** Without this, a command containing `<` or `>` would break the `parse_mode=HTML` and that alert would never arrive.
6. **The flag and the country of each IP**, right next to the `Source` line, which is what you read at a glance on a phone. It comes from a table on disk, so it **costs neither a query nor a millisecond of waiting** (section 3.4.4).

   <pre>
   [Cowrie vía Telnet]

   Event: cowrie.command.input
   Source: 153.117.13.106  🇵🇰 Pakistan
   Ver IP en AbuseIPDB
   </pre>

   It is the country where **the range is registered**, not where the machine is: an attacker behind a Dutch VPS comes out of the Netherlands. That is why it goes next to the IP and not as a "from such and such country". And if the table were missing, the alert goes out anyway, with no flag: the decoration cannot bring down a warning.

7. **It stays quiet about repetition, but not about anything new.** Without this the channel is useless: a single IP once produced **10,038 identical events in two hours**. Each IP is reported on its **first two** occurrences with a given script (the counter goes by (IP, script), so a different script sounds again from scratch) and from there on the alert goes quiet, unless the IP types something we had never seen it type. What goes unreported is not lost: it is counted and appears in the summary.

<b>Commands do not arrive one at a time.</b> The plugin splits events into two groups, and it is worth knowing before you test it or it will look as if it is not working:

- <b>Immediate</b> (`PRIORITY_EVENTS`): logins with correct credentials, and file uploads and downloads.
- <b>Batched</b> (`BATCH_EVENTS`): `cowrie.command.input` and `cowrie.command.failed`, which accumulate and are sent in a single summary when the session closes.

Forty commands in ten seconds would be forty messages and an unusable phone; batched they are a single one, which also lets you see the whole sequence at a glance. The consequence when testing is that while you are still connected over SSH <b>nothing will arrive</b> about the commands: you have to close the session with `exit`.

<b>Each IP's commands are remembered, and the cap matters.</b> To know whether an IP has typed something new, a short hash of each of its commands is stored, up to `MAX_CMDS_PER_IP`. It was at 80 and that was too few: a bot with a long script did not fit entirely in its own memory, so every pass "discovered" commands already seen and the alert never went quiet. Now it is 400. And so that it does not depend on that number, if anything has had to be forgotten about an IP it gets flagged and we stop claiming that nothing is new, because on an incomplete memory you cannot distinguish "it never did it" from "I forgot":

<pre>
Vez 341 con este guion, callada desde la 3, suena por lo de abajo
Guion 79b8b0d62de1631d
Comandos que no le habiamos visto nunca:
</pre>

The four files came with the repository in section 3.4, so they get copied into place. There is nothing to paste:

```bash
sudo cp "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/COWRIE/telegram_alert_cowrie.py" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/COWRIE/telegram-ban-watcher" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/COWRIE/telegram-ban-watcher.service" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/COWRIE/telegram-notification-ban" "/opt/dirtyland/Telegram Reports/"
```

And we check that all four are there:

```bash
ls -la "/opt/dirtyland/Telegram Reports/"
```

Telegram notifications and handling the API require a chat ID and an API token.<br>
When we create a bot with `@BotFather` on Telegram, it will return a token. If it returns no token, we generate one in @BotFather by running `/mybots`, selecting the one we care about and following what it says.

Then the most important part, once we have it: we have to start the chat and write things in it. This is very important. If we do not, the script will not work for us, and it is enough to keep writing things to the chat until running the script returns the ID.

To get the "chat_id" I wrote a script that automates this; it is in base64, which gets decoded and run. The reason it is in base64 is that visually it is a single line; it asks you for the token and finds the chat_id for you:

```bash
bash <(echo "cmVhZCAtcCAiRW50ZXIgeW91ciBib3QgdG9rZW46ICIgVE9LRU4KaWYgWyAteiAiJFRPS0VOIiBdOyB0aGVuIGVjaG8gIlRva2VuIGlzIGVtcHR5LiI7IGV4aXQgMTsgZmkKZWNobyAiT2J0YWluaW5nIENoYXQgSUQuLi4iClJFU1BPTlNFPSQoY3VybCAtcyAiaHR0cHM6Ly9hcGkudGVsZWdyYW0ub3JnL2JvdCRUT0tFTi9nZXRVcGRhdGVzIikKQ0hBVF9JRD0kKGVjaG8gIiRSRVNQT05TRSIgfCBncmVwIC1vRSAnImNoYXQiOlx7ImlkIjotP1swLTldKycgfCB0YWlsIC0xIHwgc2VkICdzLy4qImlkIjovLycpCmlmIFsgLXogIiRDSEFUX0lEIiBdOyB0aGVuCiAgZWNobyAiRXJyb3I6IE5vIGNoYXQgZm91bmQuIFNlbmQgYSBtZXNzYWdlIHRvIHlvdXIgYm90IGZpcnN0LiIKICBleGl0IDEKZmkKZWNobyAiQ2hhdCBJRDogJENIQVRfSUQiCg==" | base64 -d)
```

The "chat_id" is the value `result[0].message.chat.id`.

Once we have both the chat_id and the token, we put them inside.

```bash
sudo nano /opt/dirtyland/Telegram\ Reports/telegram.cfg
```

**The structure of `telegram.cfg` is in the repository**, at **[TELEGRAM SCRIPTS/COWRIE/telegram.cfg.example](TELEGRAM%20SCRIPTS/COWRIE/telegram.cfg.example)**. And obviously API keys, tokens and IDs are never shared with anyone, ever.

Since Python is sensitive to indentation and pasting into a terminal editor can alter it, we validate the file's syntax before mounting it (this is done with the host's Python, not the container's, because the file is not mounted inside yet):

```bash
sudo python3 -c "import ast; from pathlib import Path; ast.parse(Path('/opt/dirtyland/Telegram Reports/telegram_alert_cowrie.py').read_text()); print('sintaxis OK')"
```

Before anything else we will check that the cfg has the tokens and that the scripts carry no Windows line endings:

```bash
grep -E '^(bot_token|chat_id)' "/opt/dirtyland/Telegram Reports/telegram.cfg"; file "/opt/dirtyland/Telegram Reports/telegram-ban-watcher" "/opt/dirtyland/Telegram Reports/telegram-notification-ban"
```

We install the two scripts on the host:

```bash
sudo install -o root -g root -m 0755 "/opt/dirtyland/Telegram Reports/telegram-notification-ban" "/opt/dirtyland/Telegram Reports/telegram-ban-watcher" /usr/local/sbin/
```

We install and start the service:

```bash
sudo install -o root -g root -m 0644 "/opt/dirtyland/Telegram Reports/telegram-ban-watcher.service" /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now telegram-ban-watcher && sudo systemctl status telegram-ban-watcher --no-pager
```

We create the writable directory with the container's uid:

```bash
CU=$(sudo ps -o uid= -p $(sudo docker inspect -f '{{.State.Pid}}' dirtyland_cowrie) | tr -d ' ') && echo "uid de Cowrie visto por el host: $CU" && sudo mkdir -p "/opt/dirtyland/Telegram Reports/state" && sudo chown "$CU" "/opt/dirtyland/Telegram Reports/state" && sudo chmod 770 "/opt/dirtyland/Telegram Reports/state" && sudo chown "$CU" "/opt/dirtyland/Telegram Reports/telegram.cfg" && sudo chmod 600 "/opt/dirtyland/Telegram Reports/telegram.cfg" && ls -la "/opt/dirtyland/Telegram Reports/"
```

<b>Enabling the plugin in `cowrie.cfg`.</b> Having the file inside the container is not enough: Cowrie only loads an output engine if its section exists in the configuration.

```bash
sudo nano /opt/dirtyland/cowrie/etc/cowrie.cfg
```

And we add this at the end:

```ini
[output_telegram]
enabled = true
```

We check that it has been written:

```bash
grep -A1 "^\[output_telegram\]" /opt/dirtyland/cowrie/etc/cowrie.cfg
```

> [!WARNING]
> <b>The section name is not yours to choose, and it does not work the way you would expect.</b> Cowrie's loader (`src/twisted/plugins/cowrie_plugin.py`) does this:
>
> ```python
> engine: str = x.split("_")[1]
> output = import_module(f"cowrie.output.{engine}").Output()
> ```
>
> That is, it splits the section name on the underscore and keeps <b>the first piece</b>. A section called `[output_telegram_alert_cowrie]` would give `engine = "telegram"` and Cowrie would import `cowrie.output.telegram`, which is <b>the factory plugin</b>, not ours. And worst of all: it raises no error. A reassuring `Loaded output engine: telegram` appears in the log while our plugin has not been loaded and the alerts never arrive.
>
> That is why the section is a bare `[output_telegram]` and the plugin is mounted <b>on top of</b> the original `telegram.py` (section 3.4.2.9): on the host the file keeps its descriptive name, and what points at the name Cowrie expects is the mount's <b>destination path</b>. As a consequence, a module whose name contains underscores is unreachable for this loader.
>

The Telegram side ends up spread across three sections: here go the plugin's four files, the `telegram.cfg` with the tokens, the ban service and the `state/` mailbox; in 3.4.2.9, the three mounts that put them inside the container, and <b>up to that section the alerts still do not arrive</b>; in 3.4.2.10, the definitive `cowrie.cfg`. The second bot, the one that watches the host, is independent of all this and is set up in 3.4.4.

<b>How the plugin knows which IPs are ours.</b> The private ranges are written into it, but the VPN's exit nodes are ordinary public addresses. Without them, one of our own checks arrives as if it were an attack and the red button offers to <b>ban your own node</b>, which locks you out of the machine.

The good list is the `[blocklist]` in `config.ini`, but that file is not mounted into the container and must not be, because it carries the API keys. What we do instead is have the reporter publish just the list, with no secrets, at `/opt/dirtyland/Telegram Reports/ips-propias.txt`, and have the plugin read it from there. It is rewritten on every pass, so adding a node to `[blocklist]` arrives on its own. The file does not exist until the reporter's first pass (section 3.5), and that is fine.

#### 3.4.2.8 Emulated commands: installing the complete, already patched set.

This is the <b>second part of the sanitising</b> we started in section 3.4.2.4. There we sanitised the pickle (what Cowrie reads from disk); here we replace the <b>commands</b>, which Cowrie generates on its own and which, as they ship out of the box, give the decoy away or leak the host's real data.

The emulated shell implements each command as a Python module. Fixing them one by one on the server (pulling them out with `docker cp` and patching them with `sed`) is slow and, above all, **not reproducible**: every reinstall would mean repeating dozens of patches by hand and getting every one of them right. That is why the repository already carries **the complete set of corrected modules**; here all that is needed is to place and mount them.

The <b>70 files</b> are in **[`COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE`](COWRIE%20FAKE%20ENVIRONMENT/COMANDOS%20COWRIE)** in the repository (inside the fake environment, because they are part of it: what the attacker sees when typing a command and what they see when looking at a file have to tell the same story). What they fix, grouped:

| Group | Modules | What it fixes |
|---|---|---|
| System identity | `lsb_release`, `dpkg`, `systemctl`, `journalctl`, `uptime`, `systemd_detect_virt` | Consistency with Debian 13 + systemd; `systemd-detect-virt` does not confess the container. `dpkg` **does not carry the package list written inside it**: it reads it from the file the filesystem generator exports (3.4.2.3), from the same container the pickle comes out of |
| Hardware | `nproc`, `lscpu`, `lsblk`, `dmidecode`, `free`, `getconf` | They report the same hardware as the pickle (i5-12400, 16 GB). `free` reads the honeyfs's `meminfo` and formats it like Debian 13's `procps-ng` (`16Gi`, not `16G`). `lsblk` describes an **NVMe**, the only thing consistent with `/proc/modules`. And `getconf LONG_BIT` returns **64**, which is what Mirai's droppers check to pick a binary |
| Disks and memory | `df`, `mount`, `top` | All three were broken or lying: `df` and `mount` gave `Exec format error` and `top` returned a Vim error. Now `df` and `mount` add up with `lsblk`, with `/etc/fstab` and with `/proc/mounts`, and `top` is drawn from the processes in the same `ps_command_output.json` as `ps aux`, refreshes every 3 s and exits with `q`. In the memory header there was one space too many in each of the eight fields, because the `%9.1f` already brings its own padding, and the `Swap` line carries a full stop before `avail Mem` and not a comma: it is not a typo; that is how it is |
| Editor | `nano` (and `pico`) | A real emulation, not a canned message: it used to answer `E558`, which is a Vim error. It draws GNU nano 8.4's screen, accepts `^O`, `^X`, `^G` and `^C`, respects permissions and **saves what the attacker writes into the fake filesystem**, so a later `cat` gives it back |
| Session environment | `honeypot.py`, `printenv`, `env`, `set` | The variables a login leaves set, measured on a real Debian 13 logging in over SSH and over telnet. Cowrie set `TMOUT=1800`, which no Debian sets, exported shell variables that do not show up in `printenv`, and was missing `PWD`, `SHLVL`, `MAIL`, the `SSH_*`, the `XDG_*` and `LS_COLORS`. `printenv` did not even exist |
| **`apt`** | `apt`, `apt-get`, `ps`, `systemctl` | **It installs nothing**: it queries what is already installed by reading the same file `dpkg` does, so the two cannot contradict each other. It used to answer `E: Unable to locate package nmap`, and nmap **is** in Debian, which is to say that the "what is not there is not found" rule was a lie checkable with precisely the packages people ask for. Now it answers what `apt` answers with dpkg's lock held, which does not even get as far as checking whether the package exists; `apt update` still works because it uses a different lock, and it is held by `unattended-upgrades`, which has been added to `ps` and to `systemctl` so that the PID in the message exists. We depart from the real one deliberately in one thing: trixie's waits forever, and a hung decoy takes the rest of the attacker's script down with it. And it does not dump everything at once, which made it look as if it were doing nothing: it reveals each line as it contacts the repository, with a progress indicator only if there is a terminal |
| **`awk`** *(rewritten)* | `awk` | **The `-F` did not exist**, declared as a flag with no argument, so `awk -F: '{print $2}'` did not work in either of the two ways people type it. Now it understands `-F` (one character goes literal as POSIX requires, two or more is a regular expression), `-v`, `-f`, `--`, mawk's `-W`, and `NF` and `NR`. And it stopped claiming to be GNU Awk: on Debian 13 the default `awk` is **mawk**, so `awk --version` and `dpkg -l` contradicted each other |
| **`journalctl`** *(rewritten)* + **the pager** | `journalctl`, `paginador`, `systemctl` | It returned eleven fixed lines written by hand, always dated in July and signing as `sshd` when the `auth.log` next to it signs as `sshd-session`. Now it is generated from **the same source as the `auth.log`**, so the two logs cannot tell different stories, and it understands `-n`, `-u`, `-r`, `-p`, `-k`, `-b`, `--since`, `--until`, `--list-boots` and `--no-pager`. Since it now produces hundreds of lines, a pager was needed, and they are three different programs: systemd's runs with `LESS=FRSXMK`, bare `less` uses the alternate screen, and `more` is from util-linux and prompts with a percentage by bytes. With no terminal none of them pages |
| **`/var/log/auth.log`** *(new)* | `authlog` | The machine declared `rsyslog.service` active and `dpkg` had it as installed, but the file did not exist, because rsyslog only creates them when running. And everybody looks at that file: whoever gets in checks whether their access was recorded, and plenty of droppers do `> /var/log/auth.log`. It is generated when the session opens, with a week of history and, at the end, the attacker's own entry, which is the convincing part. It goes into the filesystem and not into the pickle, since there it would be born correct and be lying five minutes later. Three measured details: an ISO timestamp with microseconds, connections signed by `sshd-session` as of OpenSSH 9.8, and the file is `root:root` and not the `root:adm` of old |
| What the machine is listening on | `ss`, `netstat`, `ip`, `ifconfig`, `lsof` | A single table is read by both, so `ss` and `netstat` cannot disagree about what the machine is listening on even though they draw it differently, and the PIDs they declare cross-check. **There was not a single UDP socket**, with `systemd-resolved` declared active and its process in `ps`; three things that were measured on a trixie because they cannot be guessed: the stub goes with `%lo`, there is a second listener on `127.0.0.54` and the LLMNR on 5355 comes out over v4 and v6. `netstat` was failing to obey `-n` and `-p`, so a `-tulpn` showed `*:ssh` instead of `0.0.0.0:22` and left out the `PID/Program name` column, and its header always said "w/o servers" even when listing servers. `ss` was missing the `Netid` column, which the real one produces as soon as two protocols are requested, that is in the `ss -tuln` of any reconnaissance, and the widths were hardcoded with an older version's format: iproute2 6.x calculates them from the content and splits each address at the last `:`. And `netstat` no longer gives away Ubuntu's `upstart` |
| **`sed`** *(new)* | `sed` | The second most typed of the ones we could not run, 132 uses in 90 days, and it failed with `Exec format error` halfway through the attacker's script. It understands `s///` with any delimiter, addresses by number, `$`, pattern, ranges and negation, `-n`, `-e`, `-i`, `-E`/`-r`, and the commands `d p q =`; it says what it cannot do rather than pretending it applied it. The detail that cannot be guessed: `sed` uses POSIX BRE, where `(` and `+` are literals and `\(` and `\+` are the metacharacters, the other way round from Python |
| **`openssl`** *(new)* | `openssl` | Here nothing was missing; there was a contradiction too many: `openssl` is pulled in by `ca-certificates`, so it exists in the pickle and `dpkg -l` declares it, yet the interpreter answered `command not found`. Now it answers `version`, the full help, the digests from `dgst` (which openssl does not name the way they are asked for: `-sha256` announces itself as `SHA2-256`), `enc -base64`, `rand`, `prime`, `ciphers`, `list`, `s_client` and `passwd`. The `passwd` hashes and the `genrsa` key **are genuinely computed**, because a fixed one would be a giveaway: two runs would produce the same. The only thing it does not answer is `speed`, which would describe the host's performance |
| **`tr`** *(new)* | `tr` | The most typed of the ones we could not run, 276 times in 90 days, ahead of `sed`. And it did not fail quietly: the pickle declares it, so a `cat x \| tr -d '\r'` answered `Exec format error` halfway down a pipeline. It understands translation, `-d`, `-s`, `-c`, `-t`, the `[:digit:]` classes, ranges, escapes and octals. It works in bytes and not in text, since what goes through there is usually a binary |
| **`systemctl`** | `systemctl` | The footer was from an older systemd: 245 wrote `LOAD   = ...` and 257, which is the one our `dpkg` declares, puts `Legend: LOAD   -> ...` and adds two lines. And it had no `--version`: it answered with the unit list, which is what it did with any unknown option |
| **`grep`** | `fs.py` | It printed **BSD**'s usage message on a machine that claims to be Debian with GNU grep 3.11; the real one is two lines, on stderr and with exit code 2. And it did not say when something was a directory: `grep x /tmp` answered `No such file or directory` about something `ls` had just listed. Now it says `Is a directory`, and with `-s` it keeps quiet |
| **`find`** | `find` | **It did not understand `-perm`**, and `find / -perm -4000` is *the* command for looking for a way to escalate: both the `-perm` and the `-4000` slipped through the unknown-argument branch, so it listed the whole machine. Now it understands GNU find's three forms (`-4000`, `/2000`, `2755`), the symbolic ones and `-type l`, and a path that does not exist is no longer walked in silence. It also used to hang the session: each entry was resolved again from the root, four walks of the tree per file, so the cost grew with the square of the size and on a `find /` the attacker left before it answered. The tree is already in memory and is now walked once |
| **`file`** | `file`, `build-dirtyland-fs.sh`, `que_le_falta_al_senuelo.py` | A `setuid` binary came out looking like any other executable, which is exactly what anyone hunting for a way to escalate looks at; the real one marks them (`setuid ELF 64-bit`). Three more were missing: `/tmp` announces itself as `sticky, directory`, a broken link says `broken symbolic link to` and devices give `character special (1/5)`. And there was an inconsistency the other way round from the usual ones: the decoy emulated `file` while the Debian the pickle comes from does not ship it, because it is built with `--no-install-recommends`, so `file /bin/su` answered like the real thing while `which file` could not find it. It is fixed by putting `file` into `PACKAGES`, and **that requires regenerating the pickle**; `que_le_falta_al_senuelo.py` now checks both directions, what the machine claims to have and cannot run, and what it can run and does not declare |
| **The disk, in `stat`** | `stat` | It wrote `Device: 801h/2049d`, which decodes to **`/dev/sda1`, a SATA disk**, on a machine where `lsblk`, `df`, `/etc/fstab` and `/proc/modules` all talk about NVMe: it was the only one announcing a different disk, and now a test cross-checks the two modules. Besides, coreutils 9 puts `major,minor` in decimal, `Size:` goes with a tab, `Birth:` no longer says `-` because ext4 does store that date, and in `stat -t` the mode goes in hexadecimal |
| **`uptime`'s line** | `uptime`, `w`, `top` (`base.py`) | All three print the same line and it was written three times, all three differently: `uptime` and `w` padded the hours with a zero where procps pads with a space, `top` said `1 days`, and none of them knew how to write `45 min`, which is what comes out in the first hour after booting. Now it is a single function |
| **The locale** | `pstree`, `lsblk`, `systemctl` | All three draw trees and **they choose the characters according to the locale**. The decoy's session exports neither `LANG` nor any `LC_*`, so it runs in POSIX and the drawing is ASCII, yet we were writing Unicode: `├─` where `|-` belongs, and `systemctl status`'s `●` where a `*` belongs. They are tied together by a test: if someone adds a UTF-8 `LANG`, it fails and reminds you that there are three modules to repaint |
| Network | `ping` | It was wrong in four ways at once. The statistics were a fixed string, the same with six packets as with one and unrelated to the times above them. `localhost` took 50 ms with `ttl=50`, when the local round trip is hundredths of a millisecond and the TTL is 64. Any name resolved, to a made-up IP and a different one each time. And it put the parenthesis on a literal IP, which is the format for when you give it a name. Now the names come from the decoy's own `/etc/hosts` and the statistics are calculated |
| Processes | `ps` (in `base.py`), `pstree`, `pgrep` | `ps aux` came out **with no command column**: the template filled in the format string instead of the value, the line went past 80 columns before reaching `COMMAND` and `ps` truncates to the terminal's width. It also published `VSZ`/`RSS` undivided, the two run together. And `ps -ef` listed nothing, just the header, because the first argument was read BSD-style and in `-ef` it found neither `a` nor `x` nor `u`: now it understands `-e`, `-A`, `-f` and `-p PID`, which is the other way of typing it, as common as `ps aux`. The three formats are checked byte for byte against Debian 13's procps, the PPID is followed from the same tree the rest of the decoy describes rather than invented per row, and the session no longer comes frozen in the JSON: it is synthesised for whichever user is inside |
| Files and permissions | `ls`, `cat`, `find`, `stat`, `file`, `fs.py` (`cd`, `head`, `tail`, `grep`, `less`, `more`) | They apply real POSIX permissions: every other user's `/home` is private (`0750`) and only root looks inside, since Cowrie out of the box does not check read permissions. Besides, `ls -l` of a link describes it rather than resolving it, and `stat` takes the UTC offset from `%z` instead of carrying `+0300` written by hand, which is only right from March to October |
| Integrity | `md5sum`, `shasum` | `sha1/224/256/384/512sum` and `b2sum` return the real hash; they used to answer "Exec format error" |
| Escalation | `base.py` (`su`), `sudo`, `bash`, `bashbuiltins` | `su` asks for a password and, if it is right, **genuinely changes identity** (user, uid, prompt, home), and `exit` returns to the previous one. `sudo` answers like a non-sudoer to a normal user and runs the command if the caller is root; it used to ask root for a password and then answer `root is not in the sudoers file`, an impossibility that was seen in a real session. Its usage text was from the 1.8 branch while `sudo -V` declared 1.9.16p2, so the version now comes from `dpkg`'s listing. And a `sudo -V` as root is not five lines; it is 142, with compilation options, paths, sudoers *defaults* and the variables it preserves: since we accept `root/root`, that is the usual case, and the dump lives in `ayudas-comandos.json` because it is data and not code |
| **Loops** | `honeypot.py`, `bashbuiltins.py` | The body was repeated three times and that was it, so `i=0; while [ $i -lt 2 ]` went round three times where it should go twice: **the number of iterations of any counted loop was always wrong**, and counting is what a `while` is for. Now each iteration returns the body plus the loop itself, so the condition is re-examined with the environment already changed and the loop ends on its own; whatever does not end is stopped by a cap of a hundred iterations. Five more came out of that: `break` and `continue` answered `command not found`, a `break` restarted the loop until it blew the stack, an `if` inside the body ran both branches because conditionals were resolved before unrolling, a loop with something stuck to the `done` was not a loop at all, and **`algo \| while read VAR` did not exist**, which is how you walk a file line by line in any script: now the left-hand side is executed and one iteration is run per line with the variable set. And `((i++))` answered `i++: command not found` without moving the counter, because the evaluator only knew how to read; now it also assigns, and `((...))` is rewritten to `let` |
| **What was left half done** | `bashbuiltins`, `nohup`, `cat`, `honeypot.py` | **`time` answered `command not found`**, and that happens in no bash: it is not a binary; it is a keyword of the language. **`nohup` announced the file and ran nothing**, so the last line of nearly any dropper (`nohup ./x &`) did nothing and the attacker left believing their binary was running. And one that was on no list: `protocol.pp` is a single slot, and running something inside left it pointing at the inner command, so on coming back the outer pipeline lost its entire output and `eval echo hola \| cat` printed nothing. It happened with everything that relaunches a command: `eval`, `command`, `builtin`, `source`, `nice`, `timeout`, `setarch` and `env` |
| **`x86_64` was a wrapper, not a command** | `setarch` *(new)* | On Debian `/usr/bin/x86_64` is a link to `setarch`, and what it does is run whatever you put after it. Ten uses in 90 days, and the likeliest is `x86_64 -R ./payload`, which disables address space randomisation so an exploit comes out reliable: without emulating it, the inner command never ran and the chain was cut right there. The four names that link to setarch on amd64 are included, each naming itself by its `argv[0]` |
| **`head` added one line too many** | `fs.py`, `cat` | It split the file on `\n` and wrote a newline after each piece, including the empty one the trailing newline leaves, so every output carried one blank line too many and `head -2 fichero \| wc -l` on a one-line file answered 2. Pulling on that thread, two more came out: `cat -A` was accepted and did nothing, which is exactly what you type to see whether a file has tabs where it should not, and `cat -n` separated with two spaces where a tab belongs, so a `cat -n \| cut -f2` took the whole line |
| **The process's `/proc`** | `sanitize-pickle.py`, `honeypot.py`, `cat` | `cat /proc/self/status` did not return a single line, and a blank status is worse than a strange one, because there is no Linux where it comes out like that. Anything wanting to know where it has landed reads it: whether there is a debugger attached (`TracerPid`), whether it lives in a container (the `NS*`) or what privileges it has (`Cap*`). They now come out as on a real machine, with `Seccomp: 0` and `NoNewPrivs: 0` where Docker puts 2 and 1, and with the cgroup, which is what really gives a container away: a dropper checks `/proc/1/cgroup` before installing itself and if it sees `/docker/...` it turns around. **It requires regenerating the pickle.** And the owner was always root, because the status is baked in when the pickle is built with root's bash data and the pickle is the same for every session: logging in as a normal user, `id` said `uid=1004(alyosha)` and `grep Uid:` said `Uid: 0`, the same process with two owners in two consecutive commands. The lines that depend on who logged in are corrected **on read**, and every reader goes through there (`cat`, `grep`, `head`, `tail`, `less`, `more`) and not just `cat` |
| **`history` was masked by a no-op** | `base.py`, `bashbuiltins` | It answered blank and the real command already existed: Cowrie walks `command_modules` in order and the last one to register a name wins, so the good `Command_history` in `base.py` was masked by the no-op in `bashbuiltins.py`, which loads afterwards. No test caught it because each module on its own is fine: now there is one that reads the registries in load order and checks that no no-op masks an implemented command |
| **The downloaders denied their own version** | `descargas` *(new)* | `wget --version`, `curl --version` and `tar --version` failed, and that is the first thing anyone checks, because the options change between versions: a wget that cannot say which wget it is, is not a wget. The module does not rewrite all three, it inherits from Cowrie's and only steps in front to answer `--version`. And `gzip` was not there in any form even though the filesystem declares it: a `gzip -d payload.gz`, which is the step after the download in half the scripts, answered `No such file or directory` |
| **Persistence through `crontab`** | `crontab` *(rewritten)* | **`crontab -` hung the session**, and that is how a task gets installed from a script and the most used way of persisting. And what did not hang, lied: nothing was stored, so a `crontab -` followed by `crontab -l` answered `no crontab for root`. Now it is written where cron writes it (`/var/spool/cron/crontabs/USUARIO`) so that a `cat` of that path and `crontab -l` tell the same story, with the three-line header that `crontab -l` does not show |
| **`useradd` was not `useradd`** | `usuarios` *(new)* | The image had it pointing at the same class as `adduser`, and they are two different programs: `adduser` is Debian's interactive wrapper and `useradd` is shadow's binary, which prints nothing and asks nothing. A `useradd pepe` sat there asking for a password, which is to say it hung the script right where the backdoor gets created. Now shadow's five are there and what they do is genuinely written into `/etc/passwd`, `/etc/group` and `/etc/shadow`, which is the only thing that survives the next check: the attacker runs `id pepe` straight afterwards |
| **`chattr +i` and `lsattr`** | `base.py` | A `chattr +i` followed by an `lsattr` contradicted each other: the attacker protects their implant, one of the first things anyone who drops something in `/tmp` does, and the system said no flag was set. `lsattr` did not even exist. The twenty-two positions are not guessed: they were measured by setting each flag in a container with `CAP_LINUX_IMMUTABLE` |
| **`service` described another machine** | `service` *(rewritten)* | `service --status-all` answered with a fixed list containing `cups`, `lightdm`, `bluetooth`, `avahi-daemon` and `open-vm-tools`: **an Ubuntu desktop inside a VMware virtual machine**, when the cover story is a Debian 13 server. It showed up with two consecutive commands, because `systemctl` lists none of those and `dpkg -l` does not declare them. Now the list comes from `/etc/init.d` and the state from `systemctl`'s table |
| **`hostname -I` changed the machine's name** | `base.py` | The worst one there was: any argument was taken as a new name, so `hostname -I`, one of the first things anyone who has just got in types, left the attacker with a `root@-I:~#` prompt for the rest of the session. Now it understands `-a -A -b -d -f -F -i -I -s -y` and their long forms, and the IP comes from `ip.py`, so that `hostname -I`, `ip a` and `ifconfig` do not say three different things |
| **`$$`, `$(...)` and the backslash** | `honeypot.py` | Three from the interpreter. **`echo $$` printed `$$`**, and that number names half the temporary files in any script (`/tmp/.$$`): what got created was a file literally called `.$$`. **A `$(...)` substitution was resolved at tokenising time**, before the assignments on its own line had run, so `i=$(expr $i + 1)` did not advance. And **an operator escaped with a backslash became an operator again**: in `expr 2 \> 1` the `2` ended up redirected into a file called `1` |
| **`ls` was not `ls`** | `ls`, `paginador` | **It kept to columns even when the output was not a terminal**, and that is not formatting: `ls /etc \| wc -l` counted 29 where there are 60, so everything that counts or filters `ls`'s output, which is how you walk a directory from a script, came out wrong. The column layout was not its either: it wrote left to right where the real one fills each column downwards, and separated with one space instead of two. To know whether the output is going to a terminal it now looks at Cowrie's descriptor table: with `next_command` pipelines were caught but a `> fichero` was not |
| **Nine missing coreutils** | `coreutils_mas` *(new)*, `ulimit`, `env`, `uptime` | `arch`, `tty`, `stty`, `nice`, `timeout`, `realpath`, `paste`, `fold` and `expr` answered `No such file or directory`, which is the worst way to fail, because it means the machine is lying: `ls -l` shows them, `which` finds them and `dpkg -l` declares coreutils. `expr` deserves a separate mention: it is the one used by any loop written before bash had `$(( ))`, and it still turns up in droppers copied from old sources. Besides, `ulimit` had its whole body in a `pass` and `env` only knew how to list (`env -i orden` swallowed the command) |
| **The exit code on failure** | `base.py` (mixin) and the sixteen modules that inherit from it | **Almost no command set one**: they wrote their complaint and returned zero, so `cat fichero \|\| wget URL -O fichero` swallowed the fallback and the attacker watched their script carry on down the wrong branch, when trying something and having a plan B is half of what a dropper does. It is solved in one place, with a mixin that marks failure when writing to standard error, and it is inherited by hand because there are commands that write there without failing (`apt`'s warning, `wget`'s progress). The code is not always 1: `grep` and `sort` give 2. Three of them also hung or killed the session: `mkdir /noexiste/x` blew up with an uncaught `FileNotFoundError`, `tr a b fichero` did not look at the third operand and sat waiting, and `uniq` could not read files |
| **`${...}` expansion** | `honeypot.py`, `base.py`, `bashbuiltins.py` | Of the forms of `${...}` only three were understood, and not by design: the operator was looked up with a `find()` and whichever appeared first won. **Everything else came out literally on screen**, which is the worst way to fail, because no shell prints a bare `${V/b/X}`. Two said one thing and did another: `${V:=x}` returned the value without storing it, and `${V?msg}` printed itself whole when what bash does is warn and not run the command. And `$#` did not even arrive intact, because to the tokeniser that hash opens a comment: `echo $#` printed a lone dollar sign and swallowed the rest of the line. Along with that, the other two pieces of any script's argument loop: `set -- a b c` and `shift`, which was a silent no-op |
| **`local`, `return` and a group's environment** | `honeypot.py`, `bashbuiltins.py` | **Every command in a parenthesis or in a function body made its own copy of the environment**, so `(A=1; echo $A)` printed an empty line and a function could not use a variable it had just assigned itself. Now the group shares the dictionary and whoever launches it decides whether it comes back outwards: from a function yes, from a parenthesis no. And `local` and `return` always answered that they are only valid inside a function, including inside one, so **a function starting with `local`, which is half the functions in any script, did nothing** |
| **`wc`** *(rewritten)* | `wc`, `coreutils_extra` | **It printed nothing in the two normal cases**: it wrote by walking the options list, and with no options that list is empty, so `wc fichero` and `algo \| wc` produced not a single line. What had to be measured is the column width, which does not come from the figures but from the byte size of the inputs, and down a pipeline that size is not known in advance, so coreutils reserves seven: the same numbers are drawn differently depending on whether they come from a file or from a `\|`. Along the way, three versions of the same package: `cut --version` said coreutils 8.30, `chmod --version` 8.25 and `printenv --version` 9.7, on the same machine and with a `dpkg -l` that declares one. Now they come from a shared function that reads dpkg's listing |
| **`/bin/sh` is dash** | `bash.py`, `honeypot.py` | On Debian `/bin/sh` is not bash; it is dash, and Cowrie registered `sh`, `bash`, `/bin/sh` and `/bin/bash` in the same class: typing `sh` opened a shell identical to the session's, so it looked as if the command did nothing. Now `sh` drops to `$ `, its errors come out as `sh: 2: asd: not found` with the line number, and inside it the arrow keys write their escape sequence and tab inserts a tab, because dash has neither line editing nor history |
| Shell realism | `honeypot.py`, `seq`, `python`, `busybox` | `$RANDOM`, the `>` continuation prompt when a loop is left half written, real short-circuiting of `&&`/`\|\|`, and `$?` also embedded in another token (`echo rc=$?`), which used to come out literally. It is substituted just before running each command and not when parsing the line, so that `cmd; echo $?` gives `cmd`'s code and not the previous line's. And `$TERM` is filled in for telnet sessions, which do not go through SSH's `getPty()` |
| Telnet | `userauth.py` | Debian-style telnet negotiation (avoids nmap's "Cowrie" softmatch) |

<b>Our `apt` installs nothing, and that is on purpose.</b> The factory one faked the installation and gave itself away: in a real session on 30/08/2026 it strung together a `Permission denied` on the lock file for an `apt-get update` launched as <b>root</b>, the `-y` installed as if it were a package, an `i386` `.deb` on a machine that says `x86_64` everywhere, a `Segmentation fault` on running what had just been installed, and, thirty seconds after the permission denied, the same `apt-get` downloading 328 kB without a care.

Now only what is already installed is queried, reading the same `dpkg-packages.tsv` that `dpkg` uses, so the two cannot contradict each other. What is not there is not found: anyone asking for `masscan` gets `Unable to locate package`, which is the answer from a server with trimmed-down repositories. One known imprecision remains: trixie ships `apt` 3.0, with a different presentation, and here both `apt` and `apt-get` give the classic one.

<b>nano and files that cannot be written.</b> An editor that saves into `/etc/passwd` as a normal user gives the decoy away on the first attempt, and it is one of the first things anyone tries. The messages are not made up; they are those of a real GNU nano 8.4, and they come out white on red, which is the style nano reserves for permission problems.

| Situation | What comes out |
|---|---|
| File readable but not writable (`/etc/passwd` as a normal user) | `[ Directory '/etc' is not writable ]` and then `[ File '/etc/passwd' is unwritable ]` |
| Directory that cannot be traversed (`/home/mihail`, mode `0750`) | `[ Path '/home/mihail' is not accessible ]` |
| File that cannot be read (`/etc/shadow`) | `[ Error reading /etc/shadow: Permission denied ]`, the buffer comes up empty and the title becomes `New Buffer` |
| `^O` on something that cannot be written | `[ Error writing /etc/passwd: Permission denied ]`, and the file is not touched |

The check goes <b>before</b> writing. Trusting `fs.mkfile` to fail does not work, because Cowrie registers the node without looking at permissions, and then a normal user "saved" into `/etc/passwd` and nano answered `Wrote 1 line`.

<b>1. Where they are.</b> Inside [`COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE`](COWRIE%20FAKE%20ENVIRONMENT/COMANDOS%20COWRIE) the files are spread across three subfolders, according to the path they occupy inside Cowrie:

| Subfolder | Files | What they are |
|---|---|---|
| `commands/` | 42 | The emulated shell's commands |
| `shell/` | 1 (`honeypot.py`) | The interpreter: `$RANDOM`, `&&`, continuation prompt |
| `telnet/` | 1 (`userauth.py`) | The telnet negotiation |

They are already on the VPS: they were uploaded with the repository in section 3.4, so there is nothing to transfer. The modules are at `/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE` (spread across `commands/`, `shell/` and `telnet/`) and the `ps` output at `/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/ps_command_output.json`.

Before going on, we check on the VPS that the 70 modules and the JSON have arrived:

```bash
find "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE" -path '*/tests/*' -prune -o -name '*.py' -print | wc -l
ls -la "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/ps_command_output.json"
```

<b>2. Placing the modules in `cmdpatch`.</b> In the repository they are arranged according to their path inside Cowrie (`commands/`, `shell/`, `telnet/`), but on the host they all live together in a single folder: what decides which path each one goes to is the `docker-compose` in the next section. The `find` gathers them from the three subfolders and flattens them into one. The `-prune` on `tests/` is not decoration: that is where section 3.7.10's suite lives, and without it that would be copied into `cmdpatch/` and end up **mounted as one more command** inside Cowrie.

```bash
sudo find "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE" -path '*/tests/*' -prune -o -name '*.py' -exec cp -t /opt/dirtyland/cowrie/cmdpatch/ {} +
sudo chown root:root /opt/dirtyland/cowrie/cmdpatch/*.py
sudo chmod 644 /opt/dirtyland/cowrie/cmdpatch/*.py
```

In the same repository folder travels `txtcmds/`, which are **not modules**: they are canned outputs replacing Cowrie's. The `find` above does not gather them (it looks for `*.py`) and they do not go into `cmdpatch/`, because their path inside the folder **is** the binary's path on the decoy:

```bash
sudo cp -a "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/COMANDOS COWRIE/txtcmds/usr" /opt/dirtyland/cowrie/txtcmds/
sudo chown -R root:root /opt/dirtyland/cowrie/txtcmds
sudo find /opt/dirtyland/cowrie/txtcmds -type f -exec chmod 644 {} +
```

<b>Why they are needed, and why they hang off `usr/bin/`.</b> Cowrie's canned outputs live in `txtcmds/bin/`, and on a modern Debian five of them never fire (`df`, `dmesg`, `mount`, `sync` and `stty`). It is not that they lie; it is that the command breaks:

<pre>
root@pc-dev-003-ignis:~# df -h
-bash: /usr/bin/df: cannot execute binary file: Exec format error
</pre>

`getCommand()` in `shell/protocol.py` walks the `PATH` and keeps the first path where the file exists, without resolving links. Since `/usr/bin` comes before `/bin`, `df` resolves to `/usr/bin/df` and Cowrie looks for the canned output in `txtcmds/usr/bin/df`, which does not exist. Cowrie looks in `[honeypot] txtcmds_path` before its own, so it is enough to supply the ones we want to change.

| File | Reason |
|---|---|
| `usr/bin/dmesg` | Cowrie's is the boot of a <b>2009 Debian Lenny</b>, a 32-bit kernel, and it contradicts the cover story's `uname`, `/proc/version` and `/proc/cpuinfo`. Ours matches `dmidecode`, `lsblk`, the `meminfo` and `ifconfig`'s MAC |
| `usr/bin/stty` | Cowrie's is empty <b>and</b> in `bin/`, hence the `Exec format error` |
| `usr/bin/sync` | The same. It stays empty on purpose, because `sync` prints nothing, but the file has to exist |

`df`, `mount`, `getconf`, `top`, `nano` and `pico` are not fixed here: they are `commands/` modules, because a canned file does not see the arguments and `df` and `df -h` do not give the same output. The `vi` and `vim` ones are left alone, since there the `E558` comes from where it should.

<b>3. Verify.</b> There must be 70 files and all of them have to compile. This is not a formality: if a module has a syntax error, Cowrie starts up **without that command** and the attacker gets a "command not found" on a command that ought to exist, which is exactly the kind of detail that gives a decoy away.

```bash
ls /opt/dirtyland/cowrie/cmdpatch/*.py | wc -l
sudo env PYTHONPYCACHEPREFIX=/tmp/pyc-check python3 -m py_compile /opt/dirtyland/cowrie/cmdpatch/*.py && echo "los 70 modulos compilan"
```

The `PYTHONPYCACHEPREFIX` sends the compilation cache to `/tmp` so as not to leave a `__pycache__` inside `cmdpatch`, which is the folder that gets walked afterwards to generate the mounts.

<b>4. The `ps` output.</b> Cowrie does not compute it: it reads it canned from a `ps_command_output.json`. The factory one is from another machine (it shows `mysql`, `ejabberd`, `nginx`, `exim` and even `iprt-VBoxWQueue`, which gives VirtualBox away) and contains nothing of our cover story. The repository's one (**COWRIE FAKE ENVIRONMENT** folder) is consistent: systemd, NetworkManager, sshd and `admin`'s project `pm2`/`node`.

```bash
sudo cp "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/ps_command_output.json" /opt/dirtyland/cowrie/etc/ps_command_output.json
python3 -c "import json; json.load(open('/opt/dirtyland/cowrie/etc/ps_command_output.json')); print('JSON OK')"
```

<b>5. The `--help` texts.</b> Another data file, for the same reason as the previous one: these are the help texts of 49 commands, **measured from their real binaries inside a Debian 13.7**, and putting them inside the code would make both unreadable. Without this file nothing breaks (the commands behave as before) but `ls --help` goes back to listing the directory.

```bash
sudo cp "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/ayudas-comandos.json" /opt/dirtyland/cowrie/etc/ayudas-comandos.json
python3 -c "import json; d=json.load(open('/opt/dirtyland/cowrie/etc/ayudas-comandos.json')); print(len(d)-1, 'ayudas')"
```

<b>Hardly any command honoured `--help`.</b> Of the 47 modules there were, most ignored the option and did their job: `ls --help` listed the directory, `nproc --help` answered `12`, `pwd --help` came back with `/root`. Now the hook is in a single place (`runCommand`), so none of them can be forgotten, and it goes before instantiating the command so the help passes down a pipeline: `ls --help | head -3` works. `-h` is left alone, because in half of these commands it means something else (`df -h`, `ls -h`).

The help texts were measured inside a `debian:trixie` and another distribution's will not do: measured earlier on Ubuntu, 27 out of 46 did not match. The versions of the 18 packages they were measured against travel in the JSON itself, under its `_medido` key. To redo them:

```bash
docker run -d --name debian13 debian:trixie sleep infinity
```

This file arrives in step 2's transfer; if that was skipped, the `cp` will fail with a `No such file or directory` and the alternative is to write it at its destination and paste the repository's content inside:

```bash
sudo nano /opt/dirtyland/cowrie/etc/ps_command_output.json
```

Better the `scp`: it is some 1,100 lines, and pasting that volume into a terminal is slow and prone to the clipboard clipping something. Whichever way, the `json.load` validation above is what confirms it arrived whole: if the JSON is truncated, Cowrie still starts but the `ps` command stops answering.

`netstat.py` and `free.py` **come already patched** in the repository: the `netstat` points at `/run/systemd/private` instead of Ubuntu's `@/com/ubuntu/upstart`, and `free` reads `/opt/honeyfs/proc/meminfo`. The latter is the reason the pickle's sanitiser also wrote into the `honeyfs`: `free` takes the figure from disk, so both have to say 16 GB.

> [!IMPORTANT]
> The modules are mounted **read-only** on top of the image's originals, without rebuilding it. Replacing or adding any of them requires recreating the container (`--force-recreate`); a `restart` is only enough when the content of an already mounted file has been edited.

<b>6. Cowrie's `protocol.py`, patched.</b> This one **does not come from the repository**: it is a file from the image itself that we correct, just like Dionaea's `mssql.py`. It is pulled out of the container, patched and mounted on top.

What it fixes shows up in a single attempt, and it showed up on the machine: type a letter at `[sudo] password for root: `, delete it, and the cursor **backs over the prompt and eats a letter of the message**. Repeat it and the whole message is erased. The up/down arrows, moreover, **paint the previous command** in the password's place, and `Ctrl-L` repaints the input line with the password in it, in the clear.

The reason: `characterReceived()` does suppress the echo while a password is in progress, but the **editing** keys are not defined in that class (they are inherited from Twisted's `recvline`, which always writes to the terminal). And with no echo there is nothing on screen to erase, so the only thing in front of the cursor is the prompt itself.

It is pulled out of the container **every time**, including on redeployment: that way, if Cowrie's version ever goes up, the patcher finds a file it does not recognise and stops instead of mounting something half done.

```bash
sudo docker cp dirtyland_cowrie:/cowrie/cowrie-git/src/cowrie/shell/protocol.py /opt/dirtyland/cowrie/parches/protocol.py
```

```bash
sudo install -o root -g root -m 750 "/tmp/dirtyland-repo/COWRIE FAKE ENVIRONMENT/parche-protocol.py" /opt/dirtyland/cowrie/
```

```bash
sudo /opt/dirtyland/cowrie/parche-protocol.py /opt/dirtyland/cowrie/parches/protocol.py
```

**Why a patch and not the whole file.** It is 547 lines of Cowrie that are not ours and we change five methods; bringing them in would mean redoing them on every image update. It is the same treatment we give Dionaea's `mssql.py`.

Running it twice breaks nothing: it says `ya estaba parcheado` and leaves. And `test_parche_protocol.py` (section 3.7.10) does not check that the text changed: it **presses the keys** against a mock terminal, before and after, and verifies that during a password nothing reaches it. The mount is put in place by the next section's generator, which <b>stops if this file is missing</b>: a compose without that line starts up perfectly and leaves the prompt eating itself, without raising any error.

#### 3.4.2.9 Cowrie's definitive block in the docker-compose.

This is where the compose's `cowrie` service gets closed out. The service itself **already exists** from section 3.4: the pinned image, the limits, the network, the ports and the time zone were set with part 1 and are not touched. All that is missing are its mounts: the 70 command modules, the pickle, the honeyfs, the `ps` output and the Telegram alerts.

There are many of them and there is no way to shorten the list: Docker does not accept wildcards, and mounting the whole folder over `commands/` **will not do**, because it would mask the ~40 commands Cowrie already ships and only ours would be left. The alternative is not to write them by hand.

<b>1. Generate the entire `volumes` block.</b> And not just the command lines, because that part <b>grows</b>: today it is 70 modules and every command we add is one more line. Maintaining them by hand means that one day a command gets added, its mount is forgotten, and the container carries on running the factory one <b>without raising any error</b>. A failure like that goes unnoticed until an attacker sees an output that does not add up.

The script came with the repository, so all that is needed is to place it in the tree:

```bash
sudo install -o root -g root -m 750 "/tmp/dirtyland-repo/DOCKER-COMPOSE/generar-volumes-cowrie.sh" "/tmp/dirtyland-repo/DOCKER-COMPOSE/montajes-dionaea.sh" /opt/dirtyland/
```

It prints the complete block with the fixed mounts, Telegram's three and one mount per module, sending each to its correct path (`honeypot.py` to `shell/`, `userauth.py` to `telnet/`, the rest to `commands/`):

```bash
sudo /opt/dirtyland/generar-volumes-cowrie.sh
```

And with `--apply` it substitutes it directly into the `docker-compose.yml`, which is the way never to paste anything by hand again:

```bash
sudo /opt/dirtyland/generar-volumes-cowrie.sh --apply
```

Before touching anything it makes a dated backup and afterwards validates the result with `docker compose config`; if it were not valid, it restores the copy and exits with an error. Only the `cowrie` service is touched. The block is replaced <b>whole</b>, so any mounts that were already there get written again from its fixed list, and if one appeared that the script does not know about it <b>stops before touching anything</b> and names it, rather than deleting it in silence. It has to be run again **every time an emulated command is added**.

> [!WARNING]
> Generating them is preferable to writing them because the typical error does not show itself: if a mount is missing, the affected command still exists with Cowrie's original version and it is only noticed when it gives the decoy away. The most treacherous case is <b>`__init__.py`</b>: it is the list of commands Cowrie loads at startup, and it is where `shasum` is registered. If the 44 "command" files get mounted but that one is forgotten, `shasum.py` will be inside the container and `sha256sum` will still not work, because nobody has loaded it. There must be <b>45 lines</b>, not 44.

The time zone goes in twice on purpose, for the reason explained in 3.4.2.4: the `TZ` variable covers the container's processes and the `/etc/localtime` mount covers whoever reads the file.

<b>2. Validate and recreate Cowrie only.</b> The `--force-recreate` forces the container to be built from scratch so it rereads the whole configuration; a bare `up -d` may decide nothing "essential" has changed and recreate nothing:

```bash
cd /opt/dirtyland && sudo docker compose config >/dev/null && echo "compose OK"
sudo docker compose up -d cowrie --force-recreate
```

<b>3. Check that everything went in.</b> First the mount count from the host, and then that the patches are visible <b>from inside</b> the container, which is the only way to rule out the silent failure of a badly written mount.

There must be <b>70</b> `cmdpatch` mounts and <b>17</b> of the rest:

```bash
sudo docker inspect dirtyland_cowrie -f '{{range .Mounts}}{{println .Source}}{{end}}' | grep -c cmdpatch
sudo docker inspect dirtyland_cowrie -f '{{range .Mounts}}{{println .Source}}{{end}}' | grep -v cmdpatch | grep -c .
```

Those 17 are the 16 we declare ourselves (the `cowrie-var` volume, `/etc/localtime`, `cowrie.cfg`, `userdb.txt`, `fs.pickle`, the `honeyfs`, the `keys/`, the `txtcmds/`, the `ps_command_output.json`, `fs/`'s `dpkg-packages.tsv`, the `ayudas-comandos.json`, Telegram's three, the `geoip/` folder for the flags and the previous section's patched `protocol.py`) <br><b>plus an anonymous volume</b> we did not put there: `/var/lib/docker/volumes/0b698ec4d374d6d9...881a/_data`

That hexadecimal name is an <b>anonymous volume</b>: Docker creates it because Cowrie's image declares a `VOLUME` that our compose does not map. It is normal and there is no need to delete it. The ones we declare carry the project prefix (`dirtyland_cowrie-var`). To see what path it occupies inside and what the image declares:

```bash
sudo docker inspect dirtyland_cowrie -f '{{range .Mounts}}{{printf "%s  ->  %s  (%s)\n" .Source .Destination .Type}}{{end}}' | grep -v cmdpatch
sudo docker image inspect cowrie/cowrie:3.0.10 -f '{{json .Config.Volumes}}'
```

The `grep -c .` in the second command is not decoration: `println` leaves a blank line at the end and a `grep -vc` would count it as one more mount. If the numbers do not add up, better to look at the list than to guess:

```bash
sudo docker inspect dirtyland_cowrie -f '{{range .Mounts}}{{println .Source}}{{end}}' | grep -v cmdpatch | grep . | sort
```

If something unexpected appears, for instance `cowrie/output/` paths from the old mount of `netstat.py` and `free.py`, then old lines have been left in the compose: those two files now come from `cmdpatch`, so they have to be deleted or the same command would be mounted twice.

```bash
sudo docker exec dirtyland_cowrie /cowrie/cowrie-env/bin/python3 -c "
from pathlib import Path
base = Path('/cowrie/cowrie-git/src/cowrie')
print('netstat parcheado (systemd):', '/run/systemd/private' in (base/'commands/netstat.py').read_text())
print('honeypot parcheado (RANDOM):', 'RANDOM' in (base/'shell/honeypot.py').read_text())
print('shasum registrado en __init__:', 'shasum' in (base/'commands/__init__.py').read_text())
"
```

All three answers must be `True`. The last one is what confirms that `__init__.py` is mounted and that, therefore, the new commands get loaded.

```bash
sudo docker logs dirtyland_cowrie 2>&1 | grep -aE 'output engine|\[telegram\]' | tail -5
```

Two output engines must come out (`jsonlog` and `telegram`) <b>and in addition</b> a line `[telegram] tokens cargados de /opt/dirtyland/Telegram Reports/telegram.cfg`.

That second line is the one that matters: <b>our</b> plugin writes it at startup. If `Loaded output engine: telegram` appears but there is no `[telegram]` line, what has been loaded is the factory plugin and ours is inert.

> [!WARNING]
> Cowrie reads its configuration <b>only at startup</b>, so a change to `cowrie.cfg` or to a mounted file has no effect until the container is recreated. If at some point only `cowrie.cfg` is edited without touching the compose, a `sudo docker restart dirtyland_cowrie` is enough for it to reread it.

If the alerts do not arrive, we can check that Cowrie is genuinely reading the Telegram section of our configuration file:

```bash
sudo docker exec dirtyland_cowrie /cowrie/cowrie-env/bin/python3 -c "
from cowrie.core.config import CowrieConfig as c
print('enabled:', c.get('output_telegram','enabled', fallback='NO EXISTE'))
"
```

#### 3.4.2.10 The definitive `cowrie.cfg`.

Over the previous sections this file had to be opened several times. For the sake of order and clarity, here is the final, complete version, which is the one that should remain.

<b>Before the file, the host keys.</b> If Cowrie is not given any, it makes them itself with `RSA_KEY_SIZE = 2048` written into its code. A Debian 13 with OpenSSH 10 has its RSA at **3072 bits**, which has been `ssh-keygen`'s default since OpenSSH 8.0. It is a difference visible **without logging in and without authenticating**, with a scan from outside:

<pre>
nmap -p22 -sV -A [IP VPS]
</pre>

> [!CAUTION]
> <b>That `nmap` is NOT run here: here it would not work.</b> That is why it goes in a `<pre>` and not in a copyable block. The machine is <b>sealed</b> throughout section 3.4 and is not exposed until <b>3.8.2</b>, so a scan from outside answers this right now:
>
> <pre>
> 22/tcp filtered ssh
> </pre>
>
> And that is the **correct** result at this point, not a failure. It is shown because it explains <b>why</b> the host keys generated below are needed.

<pre>
| ssh-hostkey:
|   2048 ab:92:6a:... (RSA)      <-- Cowrie
|   3072 ...                     <-- lo que tendria un Debian 13 de verdad
</pre>

So Cowrie does not invent them: `ssh-keygen` generates them, the same program that creates them on any Debian. It is the usual criterion, what is stock gets copied and not invented, applied to the first thing a scanner sees:

```bash
sudo ssh-keygen -q -t rsa     -f /opt/dirtyland/cowrie/keys/ssh_host_rsa_key     -N "" -C ""
sudo ssh-keygen -q -t ecdsa   -f /opt/dirtyland/cowrie/keys/ssh_host_ecdsa_key   -N "" -C ""
sudo ssh-keygen -q -t ed25519 -f /opt/dirtyland/cowrie/keys/ssh_host_ed25519_key -N "" -C ""
```

The `-C ""` is file hygiene. <br>
By default `ssh-keygen` puts in a `usuario@maquina` comment with the <b>VPS's real hostname</b>, and it ends up written in the `.pub` and inside the private key. <br>
nmap does not see the comment over the network, because the protocol sends the key and not the label, but these files **leave the machine** in the 3.7.11 backup. Nor are they generated with `ssh-keygen -A`, because that option always writes into the host's `/etc/ssh`, which is where the server's <b>real</b> keys live: the three commands above do the same thing in the decoy's directory.

Cowrie reads the keys from inside the container, so they have to belong to it. The uid is asked for, not assumed, just as with the Telegram mailbox in section 3.4.2.7:

```bash
CU=$(sudo ps -o uid= -p $(sudo docker inspect -f '{{.State.Pid}}' dirtyland_cowrie) | tr -d ' ') && sudo chown "$CU:$CU" /opt/dirtyland/cowrie/keys/* && sudo chmod 600 /opt/dirtyland/cowrie/keys/*_key && sudo chmod 644 /opt/dirtyland/cowrie/keys/*.pub && ls -ln /opt/dirtyland/cowrie/keys
```

If the private keys are not its own, Cowrie starts up **without SSH** and says so with a `PermissionError: [Errno 13]` on `ssh_host_rsa_key` in the log; telnet, meanwhile, carries on working, so the decoy looks half alive.

It is emptied first, so as not to end up mixing the new with whatever was left over from the earlier edits:

```bash
sudo truncate -s 0 /opt/dirtyland/cowrie/etc/cowrie.cfg
```

And it is opened to paste the content inside:

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

Key by key:

- `contents_path` and `filesystem` are the two halves of the fake filesystem: the first points at the **content** (honeyfs) and the second at the **metadata** (pickle).
- `txtcmds_path` is the canned-output folder from section 3.4.2.8. It is an **override** path: Cowrie looks here first and, if the command is not there, serves its own. That is why only the ones you want to change need supplying (`dmesg`, `stty` and `sync`) and there is no risk of masking the rest, unlike what happens with `commands/`.
- `processes` is where the `ps` output comes from (the `ps_command_output.json` from section 3.4.2.8). <b>It goes in `[shell]`, not in `[honeypot]`</b>: Cowrie reads it with `CowrieConfig.get("shell", "processes", fallback=None)`, and in the wrong section that read returns `None` without a single error, so the decoy shows the factory processes, which are another machine's.
- `[ssh] version` is the banner that announces the service, and it is **the key nmap reads**. The value **is copied from a real Debian 13, not deduced**, because the banner's number and the package's do not match: the package is `1:10.0p1-7+deb13u4` (p1) and the banner says `10.0p2` (p2), because Debian applies p2's patches without raising the package version. It is obtained by bringing up the stock sshd in a `debian:13` container and reading the first line it spits out:

  ```bash
  sudo docker run --rm --network host debian:13 bash -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq --no-install-recommends openssh-server >/dev/null && mkdir -p /run/sshd && ssh-keygen -A >/dev/null 2>&1 && /usr/sbin/sshd -p 2299 -o PidFile=/tmp/p && sleep 2 && exec 3<>/dev/tcp/127.0.0.1/2299 && head -1 <&3'
  ```

  <pre>
  SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4
  </pre>

  The `--network host` is for the same reason as in section 3.4.2.3: on the VPS, `apt`'s traffic over Docker's default network falls into the firewall's `policy drop`.

Having this key set matters: with only `[shell] ssh_version`, `nmap -sV` carried on reporting `OpenSSH 9.2p1 Debian 12`, the image's default, while the rest of the decoy said trixie.
- **The Telegram alerts cover telnet with nothing to configure, and they say which way the attackers came in.** Cowrie marks `protocol` on **every** event in a session (`EventLog` sets it on creation), so the plugin does not have to deduce it from the port or from the event type. The criteria are **the same** ones SSH already had: only `login.success`, `file_download` and `file_upload` raise alerts, and commands get batched. Opening 23 does not raise the notification volume by itself; it only adds its origin.

  The alert's first line says so, which is the only thing you read in the phone's notification without opening it:

  <pre>
  [Cowrie vía Telnet]

  Event: cowrie.login.success
  </pre>

**Cowrie's `sensor` used to go there, and it was removed.** The header was `[Cowrie 9ee5ca58e312] via Telnet`. That identifier is the `sensor` field, which defaults to the <b>container's hostname</b>, that is its Docker id, so it <b>changes on every `--force-recreate`</b>. And since there is only one decoy, it did not distinguish between anything either.

  The summary is **a single one for both protocols**: there is not one for SSH and another for telnet. The session split goes on its first line:

  <pre>
  [Cowrie] Resumen --- ultimos 30 min
  Sesiones: Telnet: 91, SSH: 34
  Avisos callados: 6 (127 eventos)
  </pre>

  That split is counted **before** the filters, on `cowrie.session.connect`: if it were counted afterwards it would only reflect what has already been alerted on, and the summary is precisely the one place where traffic that generates no alert is visible.

  The first two lines say things they did not used to say, and both for the same reason (the summary claimed more than it knew):

  **The window is stated.** If in half an hour there is nothing to suppress, no summary is sent; but the counters keep running, so that period's sessions come out in the next one. That did not used to be stated and they read as belonging to their own half hour: 40 quiet sessions appeared added to the 3 from the real interval. It is not fixed by throwing them away (they would be lost); it is fixed by stating the real period, which is the time since the last summary **sent**.

  **A suppressed alert is one alert, whatever commands it holds.** It used to say `Eventos silenciados: 127`, and those 127 were the commands in the sessions that were not alerted on, not the alerts. A single suppressed session of 300 commands read as 300 hidden messages. Now both things are stated, and the big number goes in parentheses, which is where it belongs.

- **`[telnet]` is enabled**, and getting here meant fixing three things that hold each other up. They are written down because none of the three gives an error that explains itself.

  **1. The fault that brought down every session.** Cowrie requests `DO TERMINAL-TYPE` on connecting, and its own `enableRemote` returned `False` for that option. Twisted, in the branch that runs when the client accepts something *we* asked for, carries a literal assertion:

  <pre>
  def will_no_true(self, state, option):
      # Peer agreed to enable an option in response to our request.
      ...
      assert self.enableRemote(
          option
      ), "enableRemote must return True in this context (for option {!r})"
  </pre>

  That is: we asked for an option and, when they granted it, we refused it. The exception cuts the connection off after 16 ms, and since any telnet client offers TERMINAL-TYPE, **every session dropped**. The underlying cause is the usual one here: the option list was written **twice**, once in `connectionMade` and once in `enableRemote`, and they had stopped matching. Now there is only one, `OPCIONES_SOLICITADAS`, and both places use it.

  **2. The banner comes from the honeyfs, not from the configuration.** Cowrie does `read_honeyfs_bytes("etc/issue.net")`; if it is missing, it writes `ERROR: Failed to load /etc/issue.net` and uses an **empty** banner. A real Debian telnet prints that line before the `login:`, so an empty banner gives the decoy away. The honeyfs only had `/home`, so `build-dirtyland-fs.sh` now also exports `issue`, `issue.net` and `inetd.conf` **from the same container that generates the pickle**: that way the listing and the content come from the same snapshot and cannot disagree.

  **3. Decoy coherence.** A machine that answers on 23 has to look like one that serves telnet. `openbsd-inetd` and `inetutils-telnetd` are added to the generator's packages (on Debian 13 a bare `telnetd` is only a transitional wrapper) and `/usr/sbin/inetd` to the `ps_command_output.json`. Without that, anyone coming in on 23 would see a `ps aux` that does not explain how they got in.

**4. The port has to arrive, and it was not arriving.** The above is the decoy's content, and none of it is visible from outside if the packet does not come in. <b>Two</b> more pieces are needed, in two different files, and both were missing: the `docker-compose` has to publish the container's 23, and the firewall has to let it through that far.

  The five pieces (the `[telnet]` section, the negotiation, the banner, the disk's coherence and the exposure) all have to agree. The first three are checked from inside; the last is **only** checked from outside, with the `nc` from section 3.8.2.
- `idle_timeout = 3000` (50 minutes) closes **idle** sessions. The shell and telnet read it; the SSH path does not.
- `interactive_timeout = 7200` is the **absolute** cap on an SSH session, and it does not reset when you type. Its default value is 300 seconds: without this line, every SSH session drops at exactly 5 minutes, active or not, and without a message. The two limits stop sessions abandoned by bots from competing for the container's `pids_limit` and memory.
- `internet_facing_ip` makes Cowrie use the decoy's public IP instead of the container's internal one (`172.20.0.10`), which would be an inconsistent detail for whoever is inside. **The `[IP VPS]` has to be substituted**: Cowrie copies the value as it is into `SSH_CONNECTION`, and the bracket, plus the space, which leaves the variable with five fields instead of four, shows up in the first `env`.
- `[output_telegram]` is what enables the alerting engine from section 3.4.2.7. The name is imposed by Cowrie's loader, which keeps the first piece of the section name; that is why the plugin is mounted over `telegram.py`. The tokens do not go here, they go in `telegram.cfg`.

With each container path paired, thanks to the `docker-compose`, with one on the host:

| Inside the container | On the host | What it is |
|---|---|---|
| `/opt/honeyfs` | `/opt/dirtyland/cowrie/honeyfs` | the files' content |
| `/cowrie/cowrie-git/src/cowrie/data/custom-fs.pickle` | `/opt/dirtyland/cowrie/fs/fs.pickle` | the fake disk's metadata |
| `/opt/ps_command_output.json` | `/opt/dirtyland/cowrie/etc/ps_command_output.json` | the `ps` output |
| `/opt/dpkg-packages.tsv` | `/opt/dirtyland/cowrie/fs/dpkg-packages.tsv` | the `dpkg -l` list (3.4.2.3) |
| `/opt/txtcmds` | `/opt/dirtyland/cowrie/txtcmds` | the canned outputs we replace (3.4.2.8) |
| `/opt/cowrie-keys` | `/opt/dirtyland/cowrie/keys` | the SSH host keys |
| `/cowrie/cowrie-git/src/cowrie/commands/` | `/opt/dirtyland/cowrie/cmdpatch/` | the command modules |

Since only `cowrie.cfg` has been edited, in principle it is enough for Cowrie to reread it:

```bash
sudo docker restart dirtyland_cowrie
```

And straight afterwards <b>we check that the container really sees the new version</b>, which is not paranoia:

```bash
sudo docker exec dirtyland_cowrie /cowrie/cowrie-env/bin/python3 -c "
from cowrie.core.config import CowrieConfig as c
print('hostname:', c.get('honeypot','hostname'))
print('telegram:', c.get('output_telegram','enabled', fallback='NO EXISTE'))"
```

> [!WARNING]
> If an old value comes out there (or `NO EXISTE` despite having written the section), the `restart` is not enough and the container has to be recreated:
>
> ```bash
> sudo docker compose -f /opt/dirtyland/docker-compose.yml up -d cowrie --force-recreate
> ```
>
> The reason is that Docker ties a single file's bind mount to the <b>inode</b>, not to the path. If the editor modifies the file in place, the container sees the change, but several editors, `nano` among them depending on the version, write a temporary file and rename it over the top, and that creates a new inode the container no longer follows. You check by comparing the two:
>
> ```bash
> stat -c %i /opt/dirtyland/cowrie/etc/cowrie.cfg
> sudo docker exec dirtyland_cowrie /cowrie/cowrie-env/bin/python3 -c "import os; print(os.stat('/cowrie/cowrie-git/etc/cowrie.cfg').st_ino)"
> ```
>
> Python is used because Cowrie's image does not ship `stat`. It affects every individual file we mount; the directory mounts (`honeyfs`, `txtcmds`, `keys`) are not affected.

#### 3.4.2.11 Internal verification of the decoy (without exposing it).

The first thing is what is visible **before logging in**, which is what a scanner looks at. The banner and the host keys:

```bash
ssh-keyscan -p 2222 -T 10 172.20.0.10 2>/dev/null | ssh-keygen -lf -
```

<pre>
3072 SHA256:... [172.20.0.10]:2222 (RSA)
256 SHA256:... [172.20.0.10]:2222 (ECDSA)
256 SHA256:... [172.20.0.10]:2222 (ED25519)
</pre>

**The RSA has to say 3072.** If it says `2048`, Cowrie has made its own: either section 3.4.2.10's keys are not there, or they do not belong to it (check the log for `PermissionError`), or `cowrie.cfg`'s `[ssh]` does not point at them. The other two are 256 by definition, just as on a real Debian.

And that the banner is the one we announce, which is what `nmap -sV` reads:

```bash
timeout 5 bash -c 'exec 3<>/dev/tcp/172.20.0.10/2222; head -1 <&3'
```

<pre>
SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4
</pre>

**The whole suffix** has to come out, `Debian-7+deb13u4`, not a bare `Debian-7`. That `-7` is the Debian package revision, not the distribution version, but trimmed it leaves `nmap -sV` saying `OpenSSH 10.0p2 Debian 7`, which reads as a Debian 7 from 2013 serving an OpenSSH from 2026. And above all it **contradicts the configuration's own `[shell] ssh_version`**, which does carry the suffix: one thing outside and another inside.

Then the fake shell, connecting straight to the container on its internal IP:

```bash
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null alyosha@172.20.0.10
```

<b>1. Identity and content.</b>

```bash
whoami
hostname
ls -la /home
cat /etc/debian_version
uname -a
cat ~/.bashrc
```

<b>2. That no command gives the real environment away.</b> They all have to tell the same story (Debian 13, i5-12400, 16 GB, no trace of Docker or of the VPS):

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

Specifically: `cat /etc/os-release` now returns content (it used to come out empty); `free -h` says 16 GB and not the real 2 GB; `dpkg -l` lists **hundreds** of packages with Debian 13's real versions (and in particular its `openssh-server` has to be the same `1:10.0p1-7+deb13u4` the previous section's banner comes from, with `inetutils-telnetd` appearing, which is what explains port 23); `cat /proc/version` matches `uname -a` and no longer carries the `-cloud` suffix; `cat /proc/cpuinfo` shows the Intel Core i5-12400 without the `hypervisor` flag; `groups alyosha` includes the `sudo` group; `ps aux` shows the cover story's processes (systemd, pm2, node ignis-api) and none belonging to anything else; and `netstat` no longer mentions Ubuntu's `upstart`.

> [!WARNING]
> The `ps aux` deserves a careful look, because its failure raises no error. If <b>`mysql`, `ejabberd`, `www-data`, `Debian-exim`</b> or `iprt-VBoxWQueue` appear there, Cowrie is using its factory file instead of ours, and the cause is nearly always the same: the `processes` key placed in `[honeypot]` instead of in `[shell]`. Cowrie does not warn about a key it cannot find, it simply loads its default value and the decoy shows another machine's processes. That `iprt-VBoxWQueue` is, moreover, an immediate giveaway: it announces VirtualBox.

<b>3. That other users' homes are private.</b> Connected as `alyosha`, we must not be able to look inside another user's. All four commands have to answer "Permission denied" (if instead they list content, the problem is not in the modules but in the pickle: the homes will have been left at `0755`, see 3.4.2.4):

```bash
ls /home/admin/
cd /home/admin/
cat /home/admin/.bash_history
find /home/admin -name '*.env'
```

<b>4. That escalation works.</b> `su` must ask for a password, fail with a wrong one and **change identity** with the right one; on exiting, we are who we were again:

```bash
su root            # contraseña incorrecta -> "su: Authentication failure"
su root            # con la del userdb -> el prompt pasa a "#"
whoami
ls /home/admin/    # como root, ahora sí se ve
exit
whoami             # volvemos a alyosha
sudo -l            # responde como un no-sudoers
```

<b>5. That the shell behaves like bash.</b> These are the details a bot uses to probe whether there is an emulator behind it:

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

<b>And all of this should already be notifying us on Telegram.</b>

Cowrie's filesystem, commands and alerts are now finished and verified from the inside. The honeypot is still <b>not exposed</b> to the internet.

### 3.4.3 Customising Dionaea as a Windows machine.

Dionaea emulates Windows services (SMB, RPC, MSSQL) and lives on its own IP, separate from Cowrie's, because exposing Windows services and a Debian SSH on the same address is a detectable inconsistency that burns the IP's reputation sooner. In this section we give it a credible Windows identity: we reduce its services to the consistent ones and customise the SMB banner.

#### 3.4.3.1 Reducing Dionaea's services.

<b>Why turn services off rather than leave them all on?</b> More ports catch more attacks, but a real Windows does not expose SIP, MQTT, MongoDB or WireGuard at the same time. Every inconsistent port hastens a scanner cataloguing us as a decoy and burning the IP.

Dionaea ships seventeen services by default. To keep a Windows machine with few services coherent, we leave only what a real Windows would expose: SMB (445), RPC/epmap (135) and MSSQL (1433), plus NetBIOS (`nbns`), which always accompanies SMB on a Windows machine.

The directory already exists (it was created with section 3.4's tree). All that is needed is to populate it, copying the real files from the container that is already running:

```bash
for s in epmap mssql nbns; do sudo docker cp "dirtyland_dionaea:/opt/dionaea/etc/dionaea/services-available/$s.yaml" "/opt/dirtyland/dionaea/services-enabled/$s.yaml"; done
```

```bash
ls -la /opt/dirtyland/dionaea/services-enabled/
```

> [!IMPORTANT]
> It is copied from the <b>running</b> container, and not from one created on the fly with `docker create`, because in the image those files <b>do not exist</b>: the `entrypoint` generates them at startup, which is the quirk covered in section 3.4.3.3. With `docker create` the container never starts, so the `docker cp` answers `Could not find the file ... in container`.
>
> There are <b>three</b> files and the fourth is missing: `smb.yaml` <b>is not copied</b>; it is written by hand in the next section, because it is the one carrying the Windows identity. And `nbns` stays even though its port is not published: a Windows machine that speaks SMB also speaks NetBIOS, and having it configured keeps the coherence without opening anything.
>

#### 3.4.3.2 Custom SMB banner (Windows 7 SP1).

The `path` goes in single quotes and with <b>one single</b> backslash. In an unquoted YAML scalar there are no escapes, so it would end up announcing two backslashes, and anybody enumerating the shares sees that.

<b>Why Windows 7 SP1?</b> It is the system that still attracts the most automated malware over SMB (EternalBlue and derivatives), and the autogenerated name (`WIN-` plus random characters) with the default workgroup fits a data centre box with no relationship to anyone.

The `smb.yaml` **comes with the repository**, in the `DIONAEA` folder, so it gets copied like everything else and is not typed:

```bash
sudo cp "/tmp/dirtyland-repo/DIONAEA/smb.yaml" /opt/dirtyland/dionaea/services-enabled/smb.yaml
sudo chown root:root /opt/dirtyland/dionaea/services-enabled/smb.yaml
sudo chmod 644 /opt/dirtyland/dionaea/services-enabled/smb.yaml
```

Its content, so you know what it announces:

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

This is the only one of the four that is ours; the other three are Dionaea's stock ones and that is why they were copied from the container. Same criterion as with Cowrie's `issue.net`: what is stock gets copied from where it comes from, what belongs to the cover story we bring from the repository.

#### 3.4.3.3 Why Dionaea's block is already done.

**There is nothing to edit here.** The `docker-compose`'s `dionaea` service came complete with part 1 of the repository (section 3.4): its ports bound to `[IP VPS 2]`, the `DIONAEA_FORCE_INIT_CONF=1` variable and the **read-only** mount of `services-enabled`. This section exists to explain those last two, because neither can be guessed and both produce symptoms that do not point at their cause.

We check that they are where they belong (in YAML a misplaced indent is equivalent to having written nothing, and the compose does not complain):

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
> <b>`DIONAEA_FORCE_INIT_CONF=1` is not optional</b>, and the reason cannot be guessed. The image does not ship the configuration ready: it keeps it in `/opt/dionaea/template/etc` and its `entrypoint.sh` copies it at startup, but only if the destination directory does not exist:
>
> ```sh
> test ! -d /opt/dionaea/etc/dionaea && init_etc
> ```
>
> And here is the trap: by mounting our `services-enabled` <b>inside</b> that path, Docker creates the parent directories, so it already exists before the entrypoint looks. The condition fails and Dionaea starts with no `dionaea.cfg`; the variable forces the copy. The symptom, if the variable is missing, is bewildering: a restart loop repeating `Could not read config file`, which does not point at the cause.
>

> [!NOTE]
> <b>The mount is read-only (`:ro`), and that is what holds up the service reduction.</b> On <b>every</b> startup the entrypoint links the seventeen services back into `services-enabled`. The `:ro` stops it, so our four files always rule. You can see it in the log, and it is the sign that it is working:
>
> ```bash
> cp: cannot create symbolic link './etc/dionaea/services-enabled/mysql.yaml': Read-only file system
> ```
>
> Without the `:ro`, Dionaea would bring SIP, MQTT, MongoDB and company back up on the first restart, undoing section 3.4.3.1 without anyone noticing.

The mount is in place <b>from the very first startup</b>, with the directory still empty, and Dionaea starts anyway: the entrypoint populates `services-available`, which is not mounted, and that is where the three stock files we copied earlier come from. That is why this section does not touch the `docker-compose`.

Since the compose does not change, recreating Dionaea is enough for it to pick up the new services:

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml up -d dionaea --force-recreate
```

#### 3.4.3.4 What each port captures, and why.

Measured against Dionaea's database after three months. All three ports are open and under DNAT, so the difference comes from Dionaea itself:

| Port | Connections | Binaries | What it leaves |
|---|---|---|---|
| 445 (SMB) | 15,339 | **160** | It is the only module that implements enough of the protocol to accept a file being written |
| 1433 (MSSQL) | 287 | 0 | 93 SQL commands. There is no engine behind it, so `xp_cmdshell` never gets as far as running the download |
| 135 (RPC) | 135 | 0 | 25 binds and 16 requests, all reconnaissance. Not a single exploitation attempt |

That the last two yield no binaries is not a failure: they yield intelligence. On 1433 you can see some attackers deleting others' persistence, and every connection gets reported just the same, as brute force and scanning.

> [!CAUTION]
> If you query the database by hand, `mssql_command_cmd` is a **BLOB**: a `LIKE` against it never matches and returns empty **in silence**. It has to be wrapped in `CAST(... AS TEXT)`. The collector already does this.

#### 3.4.3.5 Verifying Dionaea (without exposing it).

We check that the three ports are published and bound to the new IP:

```bash
sudo docker port dirtyland_dionaea
sudo nft list chain ip nat DOCKER | grep -E '[IP VPS 2]'
```

It has to look like this:

<pre>
135/tcp -> [IP VPS 2]:135
445/tcp -> [IP VPS 2]:445
1433/tcp -> [IP VPS 2]:1433
# Warning: table ip nat is managed by iptables-nft, do not touch!
		ip daddr [IP VPS 2] tcp dport 135 counter packets 0 bytes 0 dnat to 172.20.0.20:135
		ip daddr [IP VPS 2] tcp dport 445 counter packets 0 bytes 0 dnat to 172.20.0.20:445
		ip daddr [IP VPS 2] tcp dport 1433 counter packets 0 bytes 0 dnat to 172.20.0.20:1433
</pre>

The three ports published, each bound to Dionaea's IP, and one `dnat` rule per port pointing at `172.20.0.20`. What must <b>not</b> appear is any rule with Cowrie's IP: if it does, the two decoys would be sharing an IP and the per-interface split we set up in the compose would not be taking effect.

Counters at zero are normal here: nobody has arrived yet because we are still sealed.

> [!WARNING]
> <b>`ss -tlnp` is no use here</b>: nothing will appear listening on that IP, and that is what is expected. We configured the Docker daemon with `"userland-proxy": false`, so Docker <b>does not start any process occupying the port on the host</b> and publishing is resolved entirely with DNAT in `nftables`.
>
> With the proxy at its default value you would indeed see sockets, but at the cost of a `docker-proxy` process per port and, above all, of the container seeing Docker's IP as the source instead of the attacker's. The source IP is exactly the data we want to capture.

To verify the banner we need fingerprinting tools, which we install on the host:

```bash
sudo apt install -y nmap smbclient
```

And we check that the SMB banner announces the right Windows identity:

```bash
nmap -p 445 --script smb-os-discovery [IP VPS 2]
```

It must return "Windows 7 Professional 7601 Service Pack 1", name "WIN-K7M9XQ2P4RS" and workgroup "WORKGROUP".

And, **what cannot come out of any of the three ports is the word "honeypot"**:

```bash
nmap -sV --version-intensity 2 -p 135,445,1433 [IP VPS 2]
```

<pre>
135/tcp  open  msrpc?
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s?
</pre>

All three **unidentified** is the good result. If 1433 says `Dionaea honeypot MS-SQL server`, section 3.4's patch is not in place: either the file was not mounted, or the `sed` did not take effect. And if 445 said `Dionaea honeypot smbd`, it would mean the `smb.yaml` from 3.4.3.2 is not taking effect: that nmap signature requires the factory machine name (`HOMEUSER-` plus six characters), so changing it is exactly what dodges it.

Unidentified is not the same as "looks like a Windows". nmap recognises a real Windows as `Microsoft Windows RPC` and `Microsoft Windows 7 - 10 microsoft-ds`; here it returns data that matches none of its signatures. It is a step better than announcing itself as a honeypot and a step worse than a real Windows, and it is as far as Dionaea goes, being low to medium interaction: it sustains SMB's initial fingerprint, which is what an automated scanner sees, but does not implement a full session, so an `smbclient -L` fails with `NT_STATUS_CONNECTION_DISCONNECTED`. In the same vein, `smb-protocols` shows it only speaks <b>SMBv1</b> (`NT LM 0.12`), when a real Windows 7 SP1 also offers `2.0.2` and `2.1`: it is not configurable; it is the engine. And it has a flip side worth not "fixing", because what arrives at 445 are bots looking for EternalBlue, which is to say SMBv1 precisely.

Finally, just as we did with Cowrie's IP, we check <b>from an external machine</b> (not from the VPS itself) that the new IP is still sealed:

```bash
IP2=[IP VPS 2]; for p in 445 135 1433; do nc -vz -w 3 $IP2 $p; done
```

And on Windows, which does not ship `nc`:

```powershell
$ip2 = '[IP VPS 2]'; foreach ($puerto in 445,135,1433) { $t = New-Object Net.Sockets.TcpClient; $abierto = $t.ConnectAsync($ip2,$puerto).Wait(3000); "{0,-16} {1,-6} {2}" -f $ip2, $puerto, $(if ($abierto) { 'ABIERTO' } else { 'cerrado o filtrado' }); $t.Close() }
```

It has to give us an error! `[(tcp) timed out: Operation now in progress]`, or `cerrado o filtrado` on all three if you did it from PowerShell.

> [!IMPORTANT]
> <b>Everything is still sealed. Dionaea is not yet exposed to the internet</b>, just like Cowrie.

### 3.4.4 Monitoring the real host (second Telegram bot).

This does not watch the honeypot, it watches the <b>host</b> that holds it up: it confirms that the server's activity is what is expected and warns about any deviation. It runs with a second Telegram bot, independent of Cowrie's.

<b>1. Create the bot and get its credentials.</b> As with Cowrie's, it is created with `@BotFather` and you have to <b>write something to the bot</b> before asking for the `chat_id`, or `getUpdates` comes back empty. We reuse the same base64 script from section 3.4.2.7, which asks for the token and returns the chat:

```bash
bash <(echo "cmVhZCAtcCAiRW50ZXIgeW91ciBib3QgdG9rZW46ICIgVE9LRU4KaWYgWyAteiAiJFRPS0VOIiBdOyB0aGVuIGVjaG8gIlRva2VuIGlzIGVtcHR5LiI7IGV4aXQgMTsgZmkKZWNobyAiT2J0YWluaW5nIENoYXQgSUQuLi4iClJFU1BPTlNFPSQoY3VybCAtcyAiaHR0cHM6Ly9hcGkudGVsZWdyYW0ub3JnL2JvdCRUT0tFTi9nZXRVcGRhdGVzIikKQ0hBVF9JRD0kKGVjaG8gIiRSRVNQT05TRSIgfCBncmVwIC1vRSAnImNoYXQiOlx7ImlkIjotP1swLTldKycgfCB0YWlsIC0xIHwgc2VkICdzLy4qImlkIjovLycpCmlmIFsgLXogIiRDSEFUX0lEIiBdOyB0aGVuCiAgZWNobyAiRXJyb3I6IE5vIGNoYXQgZm91bmQuIFNlbmQgYSBtZXNzYWdlIHRvIHlvdXIgYm90IGZpcnN0LiIKICBleGl0IDEKZmkKZWNobyAiQ2hhdCBJRDogJENIQVRfSUQiCg==" | base64 -d)
```

<b>The `CHAT_ID` is exactly the same as the first bot's</b>, so the command above is optional and only serves to confirm it. In a private conversation the `chat_id` is your own Telegram user identifier, and that number does not change according to which bot you are talking to.

What is different is the token, and with it the bot. Their sharing a chat number mixes nothing, because the conversation with this bot is another window. And that separation is the goal: the decoy's alerts will be constant as soon as it is exposed and the host's should be extremely rare, so mixed together they would be lost in the noise.

<b>2. Store the credentials.</b> The directory already exists; it was created with section 3.4's tree:

```bash
sudo nano /opt/dirtyland/monitor/telegram.env
```

The second bot's token and chat_id:

```bash
BOT_TOKEN="<TOKEN>"
CHAT_ID="<CHAT_ID>"
```

<b>3. Restrict the file</b>, which contains the token:

```bash
sudo chmod 600 /opt/dirtyland/monitor/telegram.env
sudo chown root:root /opt/dirtyland/monitor/telegram.env
ls -l /opt/dirtyland/monitor/telegram.env
```

The daily summary queries Dionaea's internal database, so we need `sqlite3` on the host:

```bash
sudo apt install -y sqlite3
```

We locate where Docker keeps Dionaea's volume on the host:

```bash
sudo docker volume inspect dirtyland_dionaea-var --format '{{ .Mountpoint }}'
```

And inside that volume, the database's real path:

```bash
sudo find /var/lib/docker/volumes/dirtyland_dionaea-var/_data -name '*.sqlite'
```

> [!WARNING]
> The `find` returns <b>two</b> `.sqlite` files. The good one, where Dionaea genuinely writes, is the one in the `lib/dionaea/` subdirectory:
> `/var/lib/docker/volumes/dirtyland_dionaea-var/_data/lib/dionaea/dionaea.sqlite`
> The other, at the volume's root, is empty (a leftover from initialisation). That is the path the `DIONAEA_DB` variable uses inside the daily summary's script.

<b>This database is the only thing that says whether Dionaea is still alive</b>, and that is why the daily summary looks at when the last connection it recorded was, not just how many there were today. It once got stuck in a loop and recorded nothing for five days while everything one usually checks said it was perfect: `docker ps` gave `Up 6 days`, the process existed burning a core and the DNAT kept counting packets on 445. The summary wrote "(sin conexiones)", which reads as "nobody attacked today". Neither "is it up?" nor "does the process exist?" are any use, because both were true while the decoy was dead for the purpose it serves. Now, if more than <b>6 hours</b> go by with no recorded connection, the summary says so in large letters and with the diagnostic command written out (`docker top dirtyland_dionaea`: if the `TIME` is in days, that is it).

We can check the database's schema to understand what the script queries (the table we care about is `connections`):

```bash
sudo sqlite3 /var/lib/docker/volumes/dirtyland_dionaea-var/_data/lib/dionaea/dionaea.sqlite ".tables"
```

This query to Dionaea's database from the host is necessary because Dionaea, unlike Cowrie, <b>has no output plugins for messaging services</b> such as Telegram. Its only route to an alert is for an external process (our script) to read its logs periodically.

They came with the repository, so they get copied and made executable: the sending function (`send-alert.sh`), the real-time SSH watch (`ssh-watch.sh`), the daily summary (`daily-digest.sh`), the Dionaea watch (`dionaea-watch.sh`), the access proxies' one (`proxy-watch.sh`), the rehearsal of every alert (`probar-avisos.sh`), the circuit breaker (`breaker-watch.sh`), the daily quota (`cuota-watch.sh`) and the summary's account check (`estado-cuentas.py`).

The last two warn through the host's bot and not the decoy's: when the circuit breaker trips, abuse.ch's three platforms stop publishing, because they share an account, and that is not an attack but a fault of ours, which in the honeypot's channel would be lost among dozens of alerts a day. They run every 5 minutes, use no API quota and only speak on state changes.

The other two <b>are not executed</b>; they are libraries the watchers load with `source`: `lib-ips.sh` is the shared definition of "which IPs are ours" and `lib-telegram.sh` of "how a message gets split so Telegram delivers it whole". The `chmod +x` deliberately leaves them out, because marking something without a `shebang` as executable only invites an attempt to run it.

```bash
sudo cp "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/send-alert.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/ssh-watch.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/daily-digest.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/breaker-watch.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/cuota-watch.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/lib-ips.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/lib-paises.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/lib-telegram.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/estado-cuentas.py" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/DIONAEA/dionaea-watch.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/proxy-watch.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/probar-avisos.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/comandos-watch.sh" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/auditd-watch.py" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/baneadas-diario.sh" /opt/dirtyland/monitor/
```

```bash
sudo chmod +x /opt/dirtyland/monitor/send-alert.sh /opt/dirtyland/monitor/ssh-watch.sh /opt/dirtyland/monitor/daily-digest.sh /opt/dirtyland/monitor/dionaea-watch.sh /opt/dirtyland/monitor/proxy-watch.sh /opt/dirtyland/monitor/probar-avisos.sh /opt/dirtyland/monitor/breaker-watch.sh /opt/dirtyland/monitor/cuota-watch.sh /opt/dirtyland/monitor/comandos-watch.sh /opt/dirtyland/monitor/estado-cuentas.py /opt/dirtyland/monitor/auditd-watch.py /opt/dirtyland/monitor/baneadas-diario.sh
```

<b>`proxy-watch.sh` watches the SOCKS relays used to reach the VPS.</b> Every 30 minutes it asks Mullvad's public API whether your three proxies are still `active`, and warns through the host's bot when one goes down, comes back or disappears from the list. The VPS cannot really test them, because they live inside Mullvad's tunnel and the VPS is not a Mullvad customer, but that indicator is exactly what went `false` both times a relay went down. It only speaks on state changes.

What it does not detect is a relay changing its exit IP without dropping off the list. It is rare, the symptom is that you cannot get in, and you check it by hand from your own machine:

```bash
curl -x socks5h://PROXY:1080 https://am.i.mullvad.net/ip
```

The list of relays it watches comes from a file, `proxys.conf`, and **it has to be the same** as the one in your `~/.ssh/config`. Rather than writing it out again by hand (which is asking for the two to diverge one day and for the watcher to be looking at relays you no longer use), **it is pulled from the `config` itself**.

**From your own machine** (not on the VPS), which is where the `config` is. On Linux, the relays are read and sent straight to the VPS:

```bash
grep -oE '[a-z0-9]([a-z0-9-]*[a-z0-9])?\.relays\.mullvad\.net' ~/.ssh/config | awk '!seen[$0]++' | ssh dirtyland 'cat > /tmp/proxys.conf'
```

And on Windows, the same with PowerShell (it builds the file and uploads it):

```powershell
(Select-String -Path "$env:USERPROFILE\.ssh\config" -Pattern '[a-z0-9]([a-z0-9-]*[a-z0-9])?\.relays\.mullvad\.net' -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Select-Object -Unique) -join "`n" | Out-File "$env:TEMP\proxys.conf" -Encoding ascii; scp "$env:TEMP\proxys.conf" dirtyland:/tmp/proxys.conf; Remove-Item "$env:TEMP\proxys.conf"
```

And **back on the VPS**, it gets put in place and we check that your three relays came out:

```bash
sudo install -o root -g root -m 644 /tmp/proxys.conf /opt/dirtyland/monitor/proxys.conf && rm /tmp/proxys.conf && sudo apt install -y jq && cat /opt/dirtyland/monitor/proxys.conf
```

<b>Why it is pulled from the `config` and not written out.</b> The "SIN ACCESO" warning fires when every relay in `proxys.conf` goes down, whichever they are, but the watcher only knows the ones in that file: a relay you use that does not appear here is watched by nobody. Generating it from the `config` means they cannot diverge.

`jq` is for reading Mullvad's API response without guessing. The script carries a text-based plan B in case it is missing, but that is more fragile against a format change: if `jq` is there, `jq` is used.

<b>And the country table</b>, which is what puts the little flag next to each IP. It goes in a folder of its own because Cowrie's container mounts the whole thing (section 3.4.2.9): the decoy's plugin uses it too.

```bash
sudo cp "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/geoip/paises.py" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/geoip/generar-tabla-paises.py" "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/geoip/nombres.txt" /opt/dirtyland/geoip/ && sudo chmod 755 /opt/dirtyland/geoip/*.py && sudo chmod 644 /opt/dirtyland/geoip/*.txt
```

And now **the tables get generated**. It takes under a minute and downloads some 45 MB:

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

<b>The tables do not travel in the repository, and that is on purpose.</b> They are derived data: that same script produces them from public sources and the machine rebuilds them every fortnight by cron. Versioning them would mean 17 MB rewritten whole on every regeneration, and it is the same criterion as with `fs.pickle` and `dpkg-packages.tsv`: what gets generated does not get versioned.

<b>This copy happens after creating the container (3.4.2.9) and that is fine.</b> The plugin loads the table the first time it has to place a flag, not at startup. If it loaded it at startup, on a from-scratch installation it would find the folder empty and be left with no table forever, because an `import` only happens once: the alerts would come out with no flag and nothing would say so. There is a check that verifies it stays that way.

It is checked with two known IPs:

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

The last one carries nothing and that is correct: a private IP belongs to no country, and besides it is usually ours.

They are two sources because they are two different questions. The <b>location</b> comes from [db-ip.com](https://db-ip.com), the *IP to Country Lite* database, and says where the machine is, which is what AbuseIPDB answers and what whoever looks at a flag expects; the <b>registration</b> comes from the five RIRs and says who holds the block. They agree on 92% of IPs, and where they differ is in the cloud and in leased ranges, which is the profile of the infrastructure attacks on a decoy come from, so the alert shows both when they do not match. It is looked up on disk and never over the network, by seeking through a sorted file, with no AbuseIPDB quota spent.

> [!WARNING]
> <b>`sendMessage` has three limits, and the dangerous one is the second.</b>
>
> | Limit | What happens when you exceed it |
> |---|---|
> | 4,096 characters of rendered text | The API returns 400 and the failure is visible |
> | 100 *entities*, that is formatted spans | <b>No warning</b>: it answers `"ok":true`, delivers the whole text and silently discards the surplus, from the last one backwards |
> | About 20 messages a minute to the same chat | 429, and a rejected chunk is never retried |
>
> The second has an ugly consequence: on losing its `<code>`, the attacker's IP is left loose in the text, and Telegram's client auto-links a loose IP, so the alert ends up offering a tappable link towards the attacker's machine. Hence the rule when writing these messages: <b>every hostile IP and every download URL goes inside a `<code>`</b>.
>
> `lib-telegram.sh` counts all three things and splits across several messages rather than trimming, repeating the header and numbering `(1/3)`, always on a line break so as not to leave a link half finished. It splits up to `TG_MAX_TROZOS`, which is 4: a burst of a thousand IPs would be 25 messages, above the rate Telegram accepts. What is left over is not shown and the alert says how many lines were omitted, and nothing is lost: the connections are still in Dionaea's database and the IPs still make their way to AbuseIPDB.

> [!CAUTION]
> <b>Everything the attacker writes gets escaped before going into the message.</b> The download URL Dionaea records is chosen by them, and all they need is to slip in a less-than sign for Telegram to answer `400 can't parse entities`. At that point it is not the formatting that is lost, <b>the whole alert is lost</b>, because the watcher marks the event as seen all the same: it is a cheap way of blinding us exactly when there is something to see. That is why `tg_escapar` and `tg_recortar` are applied to every foreign field, and the hash only becomes a link if it is hexadecimal.
>
> Mind one bash trap: since 5.2, a bare `&` on the right-hand side of `${var//patrón/reemplazo}` means "the text just matched", so when escaping the less-than sign that `&` expands to the character itself and the replacement leaves it as it was. The escaping does nothing and the result looks almost correct.

And a note on the malware block: <b>it is grouped by hash, and distinct connections are counted, not database rows</b>. Without grouping, a bot that uploads the same file several times fills the alert with repetitions. Besides, depending on the version, Dionaea may record the same download twice (a `.hash` incident and a `.unique` one), so counting rows would say "x4" where there were two real uploads.

It can be checked without touching the network or spending a call, from the repository itself:

```bash
bash "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/tests/test-lib-telegram.sh"
```

And the other two watchers', which also touch neither the network nor the real database (**18 ok** and **12 ok**, 0 failures):

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

<b>A "Block IP" button for each listed IP, and why that does not get out of hand.</b> Cowrie's summary shows several IPs and used to carry a single button, the most insistent one's, so at a glance it looked as if only one was actionable. The buttons do not grow without control because they follow the list, and the list was already capped at the five most insistent IPs. One per row, because an IPv6 label runs to 45 characters and two per row get cut off on a phone.

Underneath, what needed fixing was that `_update_button` sent a new keyboard with a single button, so pressing one IP's erased all the others'. Now the keyboard is derived from a state (`message_id -> {ip: estado}`) and there is a single place that draws it.

The summary's IPs are the AbuseIPDB link, not a `<code>` to copy. It is still safe: what the `<code>` prevented was Telegram turning a loose IP into a link towards `http://esa-ip`, and inside an `<a>` of ours the destination is set by us.

> [!WARNING]
> <b>Which IP `ssh-watch.sh` reports, and why it is a control and not a detail.</b> The username sshd writes to the log is chosen by whoever connects, spaces included, so the line contains the attacker's text <b>before</b> the real IP:
>
> ```
> Invalid user "admin from [IP VPS] port 22" from 203.0.113.9 port 51234
> ```
>
> By taking the first match of `from `, anyone could decide which address appears as the source in your alert. And by putting in an IP of yours, `marca_propia` would stamp it with `(nuestro 😇)`: the alert about somebody else's intrusion passed for a check of your own. It is anchored with a trailing `" port "` and the last match is taken, which is the one sshd adds. `daily-digest.sh` does the same.

It reconstructs that day's broken alert and verifies that with the old format it exceeded 100 *entities*, that with the current one it stays at 73, that the splitting respects all three limits without lying about what it trims, and that a URL with tags inside cannot bring the alert down. The result must be **54 ok and 0 failures**.

To rehearse a real burst against the real database, without waiting for it to happen again and without moving the watcher's state, `--test` accepts how many connections to look back over (40 by default):

```bash
sudo /opt/dirtyland/monitor/dionaea-watch.sh --test 400
```

It is worth doing at least once: a bare `--test` generates four lines, and four lines test nothing of the splitting.

They should all be there, and the executables should belong to `root`:

```bash
ls -la /opt/dirtyland/monitor/
```

We test the basic send:

```bash
sudo /opt/dirtyland/monitor/send-alert.sh "Prueba de conexión del sistema de monitorización del host"
```

The real-time SSH watcher is installed as a systemd service (and not as a cron job) because it has to be listening to the log continuously and reacting on the spot, not every X minutes; systemd also brings it back up on its own if it fell over and starts it with the machine:

```bash
sudo install -o root -g root -m 0644 "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/dirtyland-sshwatch.service" /etc/systemd/system/dirtyland-sshwatch.service
```

The unit **comes with the repository**, just like the ban watcher's from section 3.4.2.7, so there is nothing to type. Its content, so you know what it does:

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

<b>And the command watcher.</b> The SSH one warns that <b>somebody has got in</b>; this one tells <b>what they are doing</b>. They are two distinct halves and neither replaces the other: the first reads `sshd`'s log and does not depend on the shell; the second reads what gets typed.

The underlying idea is what makes this whole section useful: **nobody ever logs into that machine**, so the normal state of this channel is silence for weeks. That silence is the proof that there is nobody inside. A single line is reason to look.

There are two pieces. The first is installed into `/etc/profile.d/`, and it is the one that records each command in the journal:

```bash
sudo install -o root -g root -m 0644 "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/registro-comandos.sh" /etc/profile.d/dirtyland-registro.sh
```

And **it has to be loaded from `/etc/bash.bashrc` too**, which is not duplication just in case: each place covers shells the other does not see. The command is idempotent, so it can be repeated without fear:

```bash
grep -q dirtyland-registro /etc/bash.bashrc || printf '\n# Dirtyland: registro de ordenes (apartado 3.4.4)\n[ -r /etc/profile.d/dirtyland-registro.sh ] && . /etc/profile.d/dirtyland-registro.sh\n' | sudo tee -a /etc/bash.bashrc >/dev/null; grep -c dirtyland-registro /etc/bash.bashrc
```

It has to answer `1`.

> [!WARNING]
> <b>Without that second line there is a blind spot, and it is precisely the worst one.</b> `/etc/profile.d/` is only read by <b>login</b> shells, and a root shell opened with `sudo su`, `sudo -s` or `sudo bash` is not one, so nothing typed inside gets recorded: you would see `cmd=sudo su` and then absolute silence, with no error whatsoever. The hard part to spot was that it depended on how you became root, because with `sudo -i` or `sudo su -` it did work.
>
> On Debian, `/etc/profile` also loads `/etc/bash.bashrc`, so a login shell passes through both places. That is why the file carries a `DIRTYLAND_REGISTRO` guard: without it, the same command would be recorded twice.

<b>It carries no `#!` and no execute bit, and that is correct</b>: it is not executed, the shell loads it with `source`. It picks up the commands typed in an interactive `bash` <b>exactly as they are written</b>, including what a syscall auditor does not see: the *builtins* (`cd`, `export`, `history -c`) and a whole pipeline as a single line. It does not pick up what a daemon runs, nor a shell that is not `bash`, and whoever already has a shell can disable it with `unset PROMPT_COMMAND`. That is what the second half is for.

<b>And the second half: auditing the executions.</b> The above leans on `PROMPT_COMMAND`, so it only sees what is typed **in a bash**. It does not see an `sh`, nor a `python -c`, nor what a script launches, nor a binary somebody uploads and runs, and whoever already has a shell can remove it with `unset PROMPT_COMMAND`.

This looks at the level below: the `execve` system call. There is no hiding there, because **to execute anything you have to go through it**.

```bash
sudo apt install -y auditd audispd-plugins && sudo systemctl enable --now auditd && sudo auditctl -v
```

And first of all, the disk configuration, **because the real risk is not the size**:

```bash
sudo sed -i -e 's/^max_log_file *=.*/max_log_file = 8/' -e 's/^num_logs *=.*/num_logs = 2/' -e 's/^max_log_file_action *=.*/max_log_file_action = ROTATE/' -e 's/^space_left_action *=.*/space_left_action = SYSLOG/' -e 's/^admin_space_left_action *=.*/admin_space_left_action = SYSLOG/' -e 's/^disk_full_action *=.*/disk_full_action = ROTATE/' -e 's/^disk_error_action *=.*/disk_error_action = SYSLOG/' /etc/audit/auditd.conf && sudo grep -E '^(max_log_file|num_logs|max_log_file_action|space_left_action|admin_space_left_action|disk_full_action|disk_error_action)' /etc/audit/auditd.conf
```

> [!WARNING]
> <b>Some `auditd` configurations ship `disk_full_action = HALT`, which SHUTS DOWN the machine.</b> On a honeypot that is a denial of service served on a plate: anyone who generates enough events brings the server down. With the above, the ceiling is 16 MB (2 files of 8), rotating, and **with no action that stops anything**.
>
> And the size does not matter because **the log is a staging buffer**: what matters goes out to Telegram, and whatever gets rotated away can simply be lost.

The rules go in a file and not through `auditctl` by hand, because by hand **they would not survive a reboot**, and the watcher would carry on running over a log that no longer receives anything, without raising any error:

```bash
sudo install -o root -g root -m 0640 "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/AUDITD/dirtyland.rules" /etc/audit/rules.d/dirtyland.rules
```

And they get loaded:

```bash
sudo augenrules --load && sudo auditctl -l
```

Both have to come out, the 64-bit one and the 32-bit one. Without the second, all somebody needs is to run a 32-bit binary to bypass the auditing entirely.

<b>The key to all of this is the `auid`</b>: it is what makes the rule usable.

The `auid` is the user who **authenticated**. It is set at login and **cannot be changed afterwards**: not with `sudo`, not with `su`, not by entering another interpreter. It is inherited by every child process. With `auid>=1000` the rule does two things at once:

- **It captures everything a person does**, including what they do after a `sudo su` (which was exactly the shell record's blind spot).
- **And it leaves out what is not a person**: cron, systemd, and (this matters a great deal) **everything that happens inside the containers**, because those processes do not come from a login and have no `auid`. Without that filter, every command from every Cowrie attacker would arrive in duplicate and the alert would be useless.

And the watcher that reads it and sends it:

```bash
sudo install -o root -g root -m 0644 "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/dirtyland-auditwatch.service" /etc/systemd/system/dirtyland-auditwatch.service
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now dirtyland-auditwatch.service && sudo systemctl is-active dirtyland-auditwatch.service
```

To see it without waiting, using the log's last lines. **With `--seco` it comes out on screen and nothing is sent** (measuring the volume should not cost a notification):

```bash
sudo /opt/dirtyland/monitor/auditd-watch.py --test 200 --seco
```

And without `--seco`, the same but to the phone, which is how you check that the whole chain works:

```bash
sudo /opt/dirtyland/monitor/auditd-watch.py --test 200
```

An alert looks like this:

<pre>
<b>[dirtyland-auditwatch] Maquina VPS principal</b>
<b>🚨 Esto NO son los senuelos 🚨</b>
<b>3 ordenes  ---  user desde pts1, pts0</b>
<i><b>$</b> tu usuario   <b>#</b> como root   ---   <b>(+n)</b> = esa orden lanzo n programas mas por dentro</i>

<b>#</b> wc -l
<b>$</b> python3 -c import os; os.system('whoami')  <i>(+2)</i>
<b>$</b> sudo tail -60 /var/log/audit/audit.log  <i>(+1)</i>
</pre>

The first line says which service is warning and from which machine, and the second that this is not a decoy: alerts from Cowrie and from Dionaea arrive through this same chat, and an "executed commands" alert reads very differently depending on where it comes from. The `$` and `#` markers go outside the code block, because that block is there for copying the command. And the alert is sent when things quieten down, or after 2 minutes even if they do not, because with only a silence window the case that matters, somebody working inside the machine, is precisely the one that never stops.

<b>A watcher that loses what it is watching when it gets restarted is worse than not having one, because you believe you have it.</b> And both of them did: `comandos-watch.sh` followed the journal with `-n 0`, that is from this instant on, and `auditd-watch.py` jumped to the end of the file at startup, so whatever was recorded while the service was stopped was lost without trace. Now they resume where they left off, with `--cursor-file` and by noting the inode and the byte in `auditwatch.pos`.

<b>A command's innards get folded, and the `(+n)` says how many.</b> auditd shows every `execve`, including what a program launches internally: a single `augenrules --load` is thirteen of them, and unfolded, six typed commands came out as 32 lines. The `pid`/`ppid` tree alone is not enough, because folding every descendant would mean a `sudo su` swallowing whatever gets typed afterwards inside the root shell, which is what is most interesting to see. So the time is looked at as well: a child that appears within 2 seconds is part of that command. It is a heuristic, but it hides nothing in silence, because each command carries a note of how many programs were folded inside it.

> [!CAUTION]
> <b>A record of executions ends up containing secrets.</b> It happened the same day it was set up: `send-alert.sh` passed the bot token as an argument to `curl`, auditd records every program's arguments, and the token appeared published in the Telegram alert itself. It had to be revoked. Now the token goes in through `curl`'s standard input with `--config`, and there are two more defences:
>
> - <b>Our own things do not report themselves.</b> Anything mentioning `send-alert.sh`, `api.telegram.org` or `dirtyland-cmd` is discarded. As well as the secrets, that cuts a loop, because the alert is sent with `send-alert.sh`, which runs `curl` with the whole text as an argument.
> - <b>Redaction just in case</b>: bot tokens, `api_key=`, `Authorization:` and a password stuck to a `-p`, that last one only in database clients, which is where that pattern means that.
>
> Redacting too much hides exactly what you came to see, so it is better to fall short, and it does not cover everything imaginable: if you type a key into a command, consider it compromised and rotate it.

**Both records stay, and it is not redundancy**: each sees what the other cannot.

| | `dirtyland-cmdwatch` | `dirtyland-auditwatch` |
|---|---|---|
| **Where it reads from** | The shell's `PROMPT_COMMAND`, via the journal | The `execve` system call, via `auditd` |
| **What it shows** | The **line exactly as it was written** | **Every program** that runs |
| An alias (`ls`) | `ls` | `ls --color=auto` |
| A pipeline | A single line | One program per stage |
| The *builtins* (`cd`, `exit`, `export`) | **Yes** | **No**: they execute nothing, so there is no `execve` |
| `sh`, `python -c`, a bare binary | **No** | **Yes** |
| What a script launches internally | **No** | **Yes**, folded with `(+n)` |
| If somebody runs `unset PROMPT_COMMAND` | **Stops seeing** | Carries on seeing |

That is why **`exit` only appears in one and `clear_console` only in the other**, and it is neither one's failure: it is the difference between *what you typed* and *what happened*. They are batched for <b>20 seconds</b> before sending and trimmed to <b>40 lines</b> per message, because a single `apt install` is hundreds and an alert of hundreds of lines does not get read. The thresholds move with `AUDIT_VENTANA` and `AUDIT_MAX_LINEAS`.

<b>It is recorded at two moments, and both are needed.</b> The normal one is before each *prompt*; the other, on leaving the shell, because without it each session's last command was lost, which is exactly what somebody does before leaving. And the first firing records nothing; it only notes where the history was up to: on opening a shell, bash loads `~/.bash_history`, and without that guard the last line of an earlier session was recorded as freshly run.

It has been verified on a real Debian 13 that <b>it does not touch the operator's `$?`</b>: with the record in place and without it, `false; echo $?` returns the same. If it changed it, anyone checking their own exit code would be seeing ours.

The second is the service that batches what has been recorded and sends it:

```bash
sudo install -o root -g root -m 0644 "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/dirtyland-cmdwatch.service" /etc/systemd/system/dirtyland-cmdwatch.service
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now dirtyland-cmdwatch.service
sudo systemctl status dirtyland-cmdwatch.service --no-pager
```

<b>Why it batches instead of sending one alert per command.</b> One alert per line is useless: as soon as somebody gets in and works for ten minutes the phone collapses and you stop reading. What arrives is gathered and sent in one piece as soon as there is a 20 s pause, or sooner if 25 commands pile up, and it is grouped by session (user, origin and terminal), because mixing two people's commands into one message would be exactly the mistake that makes the alert useless. The directory is only shown when it changes and the exit code only if it is not `0`.

To test it without waiting for anyone, it is enough to open another session and type something:

```bash
logger -t dirtyland-cmd -p authpriv.notice -- "user=prueba tty=pts/9 from=127.0.0.1 pwd=/tmp rc=0 cmd=echo prueba del vigilante"
```

In under half a minute an alert should arrive reading `[Host] 1 orden en la maquina principal`.

<b>The "¿Me han baneado?" section</b> opens the summary, because it is the first thing one wants to know. `estado-cuentas.py` generates it, and before trusting the "No" you need to know what it checks:

It makes <b>one authenticated request</b> to each platform and looks at whether the credential is still accepted: a `401` or a `403` are what happens when an account is closed, and that gets detected the same day. What it cannot see is an account that can still read but has had publishing restricted, so it gives <b>two signals</b> and not one: the second is our own circuit breaker, which if it has tripped means abuse.ch was rejecting our submissions, and it usually warns before the `401` does.

<pre>
🛐 Todo en orden
✅ AbuseIPDB: No me han baneado  (HTTP 200)
✅ VirusTotal: No me han baneado  (HTTP 200)
✅ abusech: No me han baneado  (query_status=hash_not_found)

Mis perfiles
MalwareBazaar · ThreatFox · AbuseIPDB · VirusTotal
</pre>

**`hash_not_found` is the good answer**, even though it sounds like a failure. It asks for EICAR's hash, which is deliberately not in MalwareBazaar: what we want to know is not whether it knows that file; it is whether it <b>accepts our credential</b>. A sanctioned account answers `unauthorized` or `illegal_auth_key`, and then the alert says that yes, we have been banned.

It writes `abusech` and not `abuse.ch` on purpose: Telegram turns anything shaped like a domain into a link, and in a message whose subject is whether we have been banned, a blue underlined label is confusing. Neither the `<code>` nor a zero-width character avoids it; removing the dot is the only thing that works.

The three queries are read-only and spend one call a day of each quota, 1 of 1,000 on AbuseIPDB and 1 of 500 on VirusTotal: a reasonable price for finding out the same day instead of three weeks later. The links come from the `[perfiles]` section of `config.ini`, which gets filled out in section <b>3.5.5.1</b>; the ones still carrying their placeholder are not shown.

It can be launched on its own to test it:

```bash
sudo python3 /opt/dirtyland/monitor/estado-cuentas.py
```

The daily summary is scheduled with cron at 06:00 UTC, which in Spanish time is 08:00 in summer and 07:00 in winter.

<p>If the host does not ship cron, it gets installed:</p>

```bash
sudo apt install -y cron && sudo systemctl enable --now cron
```

And the tasks are set with this, which **opens no editor**:

```bash
sudo install -o root -g root -m 750 "/tmp/dirtyland-repo/TELEGRAM SCRIPTS/cron-dirtyland.sh" /opt/dirtyland/ && sudo /opt/dirtyland/cron-dirtyland.sh --apply
```

And it is checked by looking at root's crontab, which is where it leaves them:

```bash
sudo crontab -l
```

These five have to be there, and **nothing else** that was already there should have changed:

<pre>
0 6 * * * /opt/dirtyland/monitor/daily-digest.sh
0 6 * * * /opt/dirtyland/monitor/baneadas-diario.sh
*/5 * * * * /opt/dirtyland/monitor/dionaea-watch.sh
*/30 * * * * /opt/dirtyland/monitor/proxy-watch.sh
0 4 1,16 * * /opt/dirtyland/geoip/generar-tabla-paises.py --avisar >/dev/null
</pre>

It can be run twice: if all five are there, it says so and leaves. **It only adds, never deletes**, because root's crontab may have things that do not belong to this project, and it keeps a copy of the previous one. It recognises each task <b>by the script, not by the whole line</b>, so if you change its time by hand it neither considers it absent nor duplicates it. Without `--apply` it only says which ones are missing.

<b>`baneadas-diario.sh`</b> sends the IPs currently blocked in the firewall. It goes out at the same time as the summary but in a separate message, and that is on purpose: the summary says how the system is, this says who has had the door closed on them, and mixing them means neither gets read.

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

<b>It comes from `nftables`'s table, not from a record of ours.</b> It is the only source that says what the machine is really blocking: a file of notes falls out of date the moment somebody unbans by hand with `nft delete element`.

<b>An alert about an IP that is being banned at that very moment carries no button.</b> The filter already excluded what was banned, but the alert was queued before the ban was requested, so when the keyboard was drawn the IP was not yet on record: now it is noted before alerting. And banning an already banned IP is not an error either, which happens often because the alert is still in the chat with its button underneath. The label of one that was already there is not rewritten: if an IP was banned automatically and somebody then presses the button, it still counts as automatic, because what matters is where it came from.

<b>Automatic or manual</b> comes from the comment the banning tool left when adding it. There is a third group because for a while both routes wrote the same text, so for those bans there is no record of where they came from, and putting them under "a mano" would be asserting something unknown. The "a mano" label changed its wording, so anything carrying the old one is recognised for what it is and that group empties itself as they get unbanned or expire.

And <b>"ninguna" also gets sent</b>. A channel that only speaks when there is something is indistinguishable from a broken channel: if one day nothing arrives, you cannot tell whether there were no bans or the alert stopped working.

<b>`dionaea-watch.sh`</b>, every five minutes, is the one that reports Dionaea's activity, and it is needed because Cowrie and Dionaea do not notify in the same way: Cowrie has its output plugin inside the container and reacts on the spot, while Dionaea has nothing equivalent and its database has to be read. Without that line, attacks over SMB, RPC and MSSQL <b>would never reach the phone</b>.

<b>That second line also watches that Dionaea is still alive</b>, which is the looping hang the start of this section talks about. The only thing that distinguishes "nobody is attacking it" from "it is stuck" is when it recorded the last connection, and this script already has that database open every five minutes. If more than <b>2 hours</b> go by without a single one, it warns over Telegram with both commands written inside: `docker top dirtyland_dionaea` to confirm it, and `docker restart dirtyland_dionaea` to bring it back up.

<b>And it does not repeat the same alert every five minutes.</b> This script reports what is new since last time, and with an insistent attacker that is an open tap: one SMB scanner left a line on every pass, which is to say 288 alerts a day for a single IP. The rule is Cowrie's plugin's: each combination of <b>IP + service + port</b> alerts its first `DIONAEA_AVISOS_POR_IP` times (2) and then goes quiet. Going quiet is not forgetting, because what is suppressed is counted, comes out summarised at the end of the message and after `DIONAEA_REAVISO_HORAS` (6) alerts again with the total. <b>What never goes quiet are the downloads</b>.

<b>`generar-tabla-paises.py`</b> regenerates the flags' table on the <b>1st and 16th</b> of each month. It goes in the crontab and not in `/etc/cron.d/dirtyland-reporter`, which belongs to the reporter and gets reinstalled whole when it is updated. It downloads the five RIRs' public files, so it uses no API quota, and `--avisar` is what makes it reliable: if a download fails or arrives incomplete it does not touch the table already in place and reports it through the bot. A table from a month ago is still right about almost everything; half a table is not.

More often would serve no purpose: the RIRs publish daily, but a range changes country very rarely. And if one day it is needed by hand (after a reinstall, for instance) it is the same command without `--avisar`:

```bash
sudo /opt/dirtyland/geoip/generar-tabla-paises.py
```

To see how many days old the one in place is, without downloading anything:

```
/opt/dirtyland/geoip/generar-tabla-paises.py --comprobar
```

We test both manually without waiting for cron:

```bash
sudo /opt/dirtyland/monitor/daily-digest.sh
```

```bash
sudo /opt/dirtyland/monitor/dionaea-watch.sh --test
```

The `--test` reports the most recent events <b>without</b> marking the state as read, so it can be launched as many times as needed to check that sending works without missing anything from the first real alert.

It takes the tokens from section 3.4.2.7's `telegram.cfg`, the same bot Cowrie uses, and not from the monitor's `telegram.env`, which is another conversation. If it answers `no pude leer bot_token/chat_id`, that file is missing or short of those keys.

## 3.5 Reporting to the platforms.

All this effort has to produce some product or service, and that is contributing to threat intelligence platforms.

The honeypot is not only for analysing the attacks you receive, but for taking that information and putting it to use.

The reporter is <b>a single program</b> that serves both honeypots.

The structure is as follows:

| Folder | What it does | What it does NOT know |
|---|---|---|
| `collectors/` | They read Cowrie and Dionaea and translate their logs into a common model | That the platforms exist |
| `reporters/` | One per platform. They apply its rules and publish | Which honeypot what they publish came from |
| `common/` | Model, state, rate limits, HTTP transport and the IP barrier | - |
| `orchestrator.py` | Chains everything in the right order | - |

That is why a single AbuseIPDB module serves both Cowrie and Dionaea without a single per-honeypot conditional: what reaches it is the same object in both cases.

However, in this section it is set up in "simulation mode", that is, without publishing anything. Section 3.8 is where the API keys for each platform are added, the machine is exposed to the internet and it actually starts reporting and working.

### 3.5.1 What goes to each platform.

Each platform accepts some findings and not others:

| Captured artefact | Platform | What gets sent |
|---|---|---|
| Attacking IPs | AbuseIPDB | The bare IP, with categories. The port goes in the comment. The server's IP, Mullvad's, the proxies' and your home IP are not uploaded. |
| Captured binary | VirusTotal | The file; and if it is malware (3.5.3, step 4), a signed comment and a "malicious" vote |
| Captured binary | MalwareBazaar | The file, **only after VirusTotal's verdict**. We have set a cap of 5 uploads a day and 20 a week. |
| URL that served the binary | URLhaus | The URL, with `threat = malware_download` |
| Confirmed infrastructure | ThreatFox | The IOC as `ip:port` or domain, with a Malpedia family name |

### 3.5.2 How do we do it?

The most important question of all. I got banned by one of the platforms for thinking that, as long as it was a malicious binary, it did not matter what I published, how much of it or exactly which binary it was.

The decision was to automate the whole process, even though the ideal would be to analyse each sample by hand and then publish it.

I believe I have found **the method for not getting banned again**.

Let's start with the easy part. Each platform is more or less picky:

- **VirusTotal**: Barely demanding, if at all.
- **AbuseIPDB**: Hardly demanding.

However, the three platforms we have left, which belong to abuse.ch, are very demanding and strict: you simply have to comply with what they ask:

- **MalwareBazaar**: abuse.ch's own founder asked me to stop publishing WannaCry. It is not in their policies; it was simply a request. Unfortunately, their intentions are not always reflected exactly and precisely in the policies on their site.
- **ThreatFox and URLhaus**: They are strict; following the policies is enough. Nothing new or surprising.

So:

- Since AbuseIPDB only wants IPs published and that's it, there is no problem to solve and no special method. Simply publish the IPs that are not yours (not your server's, not Mullvad's or the proxies' and not your home IP) and respect the daily cap AbuseIPDB sets; you might exceed it.
- On VirusTotal you do not really publish anything, and you do not get credit the same way you do on the abuse.ch platforms. Although you can upload files to VirusTotal, usually the only way to show you were the first to upload something is basically by being the first to comment in the binary's comments section and vote, nothing more. Again, there is nothing special to keep in mind.

#### 3.5.2.1 The problem.

The platforms we have left are abuse.ch's, and they are the strictest. However, aiming for 100% automation and compliance is hard.

The hard finding is the binary, not the IP, the URL or the IOC.

Attackers often drop or generate 3 types of files:
- Filler, literally empty files (you will usually see them as Andromeda).
	- Although they serve a purpose, what they do makes no sense in our case, because we are a server and not an IoT device. 
- Droppers, "_harmless_" files because all they do is curls and downloads: if you analyse one with VirusTotal, almost nobody flags it as malicious, because it really is not. A script containing curls and wgets does not have to be considered malware. Even so, we have called it by its exact name, dropper, because its purpose is anything but benign: downloading the real malware from C2 servers.

Let's stop for a moment to point out that **those two cases** have something in common: they are files of few lines or none, that is: **a size of a few bytes or 1 KB at most.**

And the third case:
- The binary itself is malicious, and that's it.

### 3.5.3 The method.

So.

We need a filter:

1. The first thing is to check the file's size. If it is 0 bytes, like the Andromeda ones, it is discarded.
2. Droppers are not malware in themselves and are not as large as malware either. But you have to sort out what is a dropper and what is a script with curls and wgets. If it is plain text of 512 bytes or less without `#!`, it is discarded, because it cannot be executed. If it has `#!`, it goes on to VirusTotal.
   - The `#!` is the first line of a file, and it indicates a script.
   - Or also if it is an ELF, or a PE on Windows.
   - Or an archive: `.zip`, `.gzip`.
3. Then each binary/script is uploaded to VirusTotal. If it was already registered, fine; if not, it is uploaded for analysis. From the analysis we collect:
   - The family and name.
   - The score the engines gave it (sometimes subjective and variable).
4. What confirms that it is a malicious binary:
   - The score: if 12 or more engines say it is, then it is.
   - If 3 or more engines classify it as family X, then it is.
   - That it is not adware or a PUP.
5. So, if it is malware, we continue; if not, the process ends here.
6. If it is malware, we vote on VirusTotal that it is (Community down vote) and post a comment.
   - We do this because there are bots on VirusTotal literally waiting for someone to upload something to MalwareBazaar, to steal it from you, upload it to VT and claim they were the first to do it, and this is real and true: they steal other people's credit and effort. What's more, they even steal the comment you posted on MalwareBazaar, so it is recommended that you put your username in the comment you post on MB, to "poison" that theft: even if they steal it, it shows whom they stole it from, because they do not even credit who they stole it from, and since it is automated, nobody usually checks.
7. Now that we know it is malware, we need to check that the family is not WannaCry (it is enough for one engine to call it that). If it is not, we continue.
8. Finally, this is where we check whether that malware already exists on MalwareBazaar: if it is published, we discard it. If it is not, and it has been on VirusTotal for 10 days or less, we publish; if not, we discard it.


### 3.5.4 Full flow.

- **The core is a file called:** `orchestrator.py`.
- Every 15 minutes, cron runs a script: `malware-watch.sh`.
- This `malware-watch.sh` script is what launches `orchestrator.py`.
	- **Why one script to call another, instead of calling `orchestrator.py` directly?**
	- Because `malware-watch.sh` contains `flock` (which, strictly speaking, the orchestrator could have directly).
		- `flock` is a Linux command, not a Python one.
		- It aims to solve a very specific problem. VirusTotal only allows 500 requests a day and 4 requests a minute. <br>`flock` is a command that locks files; the idea is that it does not allow a second run of `orchestrator.py` (_we will explain later exactly what_ `orchestrator.py` _does, but basically it is in charge of collecting, analysing and uploading_). <br>
		- All of that is a long process, and cron runs every 15 minutes no matter what. <br><br> Meaning that there is no point running `orchestrator.py` again if in those 15 minutes it has not physically had time to do everything.
		- The problem is not only that the runs overlap, but that they upload the same thing twice to the platform.
		- For that, `flock` locks when `orchestrator.py` runs and unlocks when it finishes, so that on the next 15-minute cron run it can be executed normally again. Without it running twice at the same time.
	- So that there is a trace of the failures `orchestrator.py` cannot write to its own log: broken configuration or Python failing to start. 
- So, when `orchestrator.py` can run, its job is:
	- Close what was left half done in the previous run: check whether what was being sent when it was cut off arrived.
	- Read the Cowrie and Dionaea logs: attacking IPs, binaries and download URLs.
	- Report the attacking IPs to AbuseIPDB. Always, because it does not depend on VT.
	- With the new binaries: apply the filter from 3.5.3 and upload to VirusTotal the ones it does not know.
	- With the binaries that are due for judgment: look at VirusTotal's verdict and, if it is malware, comment and vote on VirusTotal, then upload to MalwareBazaar, URLhaus and ThreatFox, and report the server that served the binary to AbuseIPDB.
	- Leave the summary of the pass in its log.
	- The error handling we explain in section `3.5.4.1`.

IPs and IOCs pose no special challenge. The hard part is the binaries, and we already saw in 3.5.3 how they are handled.

#### 3.5.4.1 If VirusTotal is not working.

VirusTotal plays an important role in the flow: two possible scenarios have to be anticipated:

**Case 1: The VirusTotal platform is down.** <br>
**Case 2: Exceeding the VirusTotal request quota.**

<p>
In both cases, uploads to MalwareBazaar, ThreatFox and URLhaus are paused. The samples stay in the "pendiente_de_veredicto" state.<br>
Why?<br>
<b>Without VirusTotal it is not possible to prove that a binary is malware</b>, and therefore not that the URL or the server that distributed it was serving malware either. So, without a verdict, nothing is uploaded to those three platforms.

<b>With AbuseIPDB, things carry on as if nothing happened</b>, except for the report on the server that served the binary, which also waits.
</p>
<p>
<b>The only difference is that in case 2</b>, we need to know when the quota resets. That is because, if we send requests just to see whether we can, VirusTotal returns `HTTP: 429` responses, and that can end in a ban.

Luckily, it is very simple: at 00:00 UTC, the VT counter goes back to zero and we can send requests again, up to 500. It is not a timer you have to wait out, and you do not have to ask how much is left: we keep count ourselves and stop before reaching 500.
</p>

### 3.5.5 Installing the reporter.

We need `python3-requests`:

```bash
sudo apt install -y python3-requests
```

First the destination is emptied, keeping `config.ini` if it already exists (that way the same command works for installing and for updating, without leaving old files lying around):

```bash
sudo find /opt/dirtyland/platform-reporter -mindepth 1 -maxdepth 1 ! -name config.ini -exec rm -rf {} + && sudo cp -a "/tmp/dirtyland-repo/REPORTING PLATFORM SCRIPTS/." /opt/dirtyland/platform-reporter/ && sudo chown -R root:root /opt/dirtyland/platform-reporter && sudo find /opt/dirtyland/platform-reporter -type f -name '*.py' -exec chmod 640 {} + && sudo chmod 750 /opt/dirtyland/platform-reporter/orchestrator.py /opt/dirtyland/platform-reporter/malware-watch.sh && echo "reporter instalado"
```

It has to finish by printing `reporter instalado`.

The state and log directories:

```bash
sudo install -d -m 750 -o root -g root /var/lib/dirtyland-reporter /var/log/dirtyland-reporter
```

#### 3.5.5.1 Configuration and blocklist.

The config is installed with the right permissions:

```bash
sudo install -m 600 -o root -g root /opt/dirtyland/platform-reporter/config.ini.example /opt/dirtyland/platform-reporter/config.ini
```

<b>Five things</b> get filled in here:

| Key | Section | Required | What to put |
|---|---|---|---|
| `ips` | `[blocklist]` | **Yes.** The program refuses to start with the list empty | The IPs of the proxies and of the VPN server itself that you use, that is, 3 proxies + 1 server. The two VPS IPs are already there |
| `cowrie_log_tz` | `[paths]` | Yes, if the Cowrie container does not run in UTC | The time zone of the Cowrie container (here `Europe/Kyiv`), the one attackers see and the one Cowrie writes its logs in. The reporter uses it to convert those times to UTC before publishing to the platforms |
| `attribution_tag` | `[general]` | No. Without it, what is published is not signed | Your handle |
| `usuario` | `[threatfox]` | No. Without it, the summary cannot tell a new IOC from a refresh | Your name exactly as ThreatFox shows it |
| The six links | `[perfiles]` | No. Without them, the daily summary does not show your profiles | Your ID in each link, instead of `TU-ID` |
| `virustotal`, `abusech`, `abuseipdb` | `[api_keys]` | No. They are added in 3.8.1 | - |

Each item is far from the others, with long blocks of comments in between.<br>
<b>To solve that, do not look for anything by eye:</b>

```bash
sudo awk '/^\[/ {sec=$0} sec=="[perfiles]" || /^(ips|cowrie_log_tz|attribution_tag|usuario)[ \t]*=/ {if ($0 !~ /^[ \t]*(;|#|$)/) printf "%4d  %s\n", NR, $0}' /opt/dirtyland/platform-reporter/config.ini
```

It tells you which lines each item is on. Now that we know the lines, we open nano showing line numbers:

```
sudo nano -l /opt/dirtyland/platform-reporter/config.ini
```
When you finish editing, let's list **every placeholder that is still not replaced**:

```bash
sudo grep -nE '^[^;]*<[^>]+>' /opt/dirtyland/platform-reporter/config.ini
```

The three `api_key` entries at the top show up on purpose: they are filled out in 3.8.1, and the `usuario` in `[threatfox]` can keep its placeholder if you prefer not to set it.

- **If you change VPN node, add it to `ips` before using it.** One IP too many in the list does no harm; a missing one does, because the reporter would end up reporting you.
- **What gets published is in English, for OPSEC.** VirusTotal and AbuseIPDB comments are public and permanent: Spanish would narrow down the profile of whoever is behind it, and English is also what is expected there.
- **`anonymous`:** the three abuse.ch platforms accept it on every submission, with `1` publishing without a name and `0` attributing it to your account. The reporters send `0`.
    - It is not the same as `attribution_tag`: `anonymous` decides whether the platform recognises you as the submitter, and `attribution_tag` writes your handle **inside the text**, which is the only thing that survives if someone republishes the sample elsewhere.
- **Your handle must never appear inside the honeyfs.** It would be the thread linking the decoy to whoever runs it.
- **To confirm the time zone of the Cowrie container:**

```bash
sudo docker exec dirtyland_cowrie /cowrie/cowrie-env/bin/python3 -c "import time; print(time.tzname)"
```

#### 3.5.5.2 Checks.

All the reporter commands need `sudo`: `config.ini` is `600` and owned by `root`, and the reporter cannot read the file without `sudo`.

<b>1. Is the code OK?</b> Two test suites that need no keys, no network and no honeypot: they work with fake data.

```bash
sudo python3 /opt/dirtyland/platform-reporter/tests/test_gates.py
```

It checks the gates one by one: that nothing is published with 4 engines, that a 30-day-old sample is rejected, that the same hash is never sent twice, that nothing is reported to AbuseIPDB without a handshake and that one of our own IPs aborts the submission.

```bash
sudo python3 /opt/dirtyland/platform-reporter/tests/test_end_to_end.py
```

It runs the full orchestrator with a fake `cowrie.json` and `dionaea.sqlite`, and checks that VirusTotal goes before MalwareBazaar, that a second pass repeats nothing and that none of our own IPs and no key appears in what would have been sent.

Both finish with <b>code 0</b> if everything passes. They have to be run again after touching any threshold or policy.

<b>2. Is my configuration OK?</b>

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --self-test
```

It checks the configuration, the permissions and the IP barrier: that our own IPs are rejected and a foreign one passes. If you have not set the `api_key` entries yet, it will exit with code 3, and that is correct: it complains about them.

<b>3. Does it work on my machine?</b> A dry run: without `--live` it publishes nothing.

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini
```

If there is no `api_key`, each platform is skipped entirely, so it only proves that the reporter starts and reads the logs. With the `api_key` entries in place, during the simulation days, this tells you why each thing was not sent:

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --show-rejections 30
```

<pre>
abuseipdb    handshake     45.9.148.99   sin handshake TCP confirmado: la politica prohibe...
malwarebazaar antiguedad   7794cb2e...   vista por primera vez hace 30 dias, el maximo son 10
</pre>

| Exit code | Meaning |
|---|---|
| 0 | All well |
| 1 | Unexpected error |
| 2 | Configuration problem |
| 3 | The self-test failed |
| 4 | Finished with network errors or platform rejections |
| 5 | Quota exhausted (not a failure) |

#### 3.5.5.3 Automating it with crontab.

As we documented in section `3.5.4`, "crontab" is used to automate it; the script it runs, as we said, is `malware-watch.sh`:

```bash
MODO=$(grep -qE '^[[:space:]]*\*/15 .*malware-watch\.sh --live' /etc/cron.d/dirtyland-reporter 2>/dev/null && echo live || echo sim) && sudo install -m 644 -o root -g root /opt/dirtyland/platform-reporter/cron.d/dirtyland-reporter /etc/cron.d/dirtyland-reporter && { [ "$MODO" = live ] && sudo sed -i -E 's|^(\*/15 .*malware-watch\.sh)$|#\1|; s|^#(\*/15 .*malware-watch\.sh --live)$|\1|' /etc/cron.d/dirtyland-reporter; true; } && grep -vE '^\s*(#|$)' /etc/cron.d/dirtyland-reporter | grep malware-watch
```
The cron file has two almost identical lines, and only one is active: the other has a # in front, which disables it.

**The previous command shows you the line that ended up active.**

It should have ended up like this:

<pre>
*/15 * * * * root /opt/dirtyland/platform-reporter/malware-watch.sh
#*/15 * * * * root /opt/dirtyland/platform-reporter/malware-watch.sh --live
</pre>

If you wonder why 15 minutes, running it more often does not speed anything up:
- Binaries are judged hours later. A sample is uploaded to VirusTotal and its verdict is checked 12 hours later, once the engines have analysed it. Checking every 3 minutes does not make it faster.
- Every pass uses up quota. It queries VirusTotal, which only allows 500 a day. More passes would mean more queries for nothing.
- Fifteen minutes is a middle ground: frequent enough to report attacking IPs early and pick up new binaries, without wasting quota. It is not a number that has to be exact; it is the one that was chosen.

If by any chance we want to look at the cron file where all of the above lives:

```bash
cat /etc/cron.d/dirtyland-reporter
```

Inside we would see:

<pre>
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

*/15 * * * * root /opt/dirtyland/platform-reporter/malware-watch.sh
#*/15 * * * * root /opt/dirtyland/platform-reporter/malware-watch.sh --live

17 6 * * * root /usr/bin/python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --self-test

*/5 * * * * root /opt/dirtyland/monitor/breaker-watch.sh

5,20,35,50 * * * * root /opt/dirtyland/monitor/cuota-watch.sh
</pre>

#### 3.5.5.4 Monitoring, pausing and what to do if you get banned.

<b>See what is going on.</b> What was sent and what was rejected:

```bash
sudo tail -n 40 /var/log/dirtyland-reporter/reporter.log
```

With `-f` instead of `-n 40` it follows live until you stop it with `Ctrl+C`. If something does not add up, `-v` shows the discards one by one, and `--only` collects from a single decoy to see which of the two has gone silent:

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini -v
```

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --only dionaea
```

<b>Submissions cut off halfway.</b> If a publication is cut off by a `timeout`, a `500` or the network, there is no way to know whether it arrived: the server may have processed it and gone down while answering. That is why it is not blindly resent, because that is what creates duplicates. It stays in the <b>sin confirmar</b> state, and on the next pass the platform is asked whether it arrived, when the platform allows it. Whatever cannot be resolved is considered lost after 24 hours.

<b>The abuse.ch circuit breaker.</b> MalwareBazaar, ThreatFox and URLhaus are the same account: a ban on one takes down all three. That is why three abuse.ch rejections in 24 hours switch all three off until they are rearmed by hand, after you understand what happened:

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --reset-breaker
```

VirusTotal and AbuseIPDB are separate accounts and keep working.

<b>Pause.</b> To stop sending to abuse.ch and keep going with AbuseIPDB and VirusTotal, disable the abuse.ch sections in `config.ini`:

```ini
[malwarebazaar]
enabled = false

[threatfox]
enabled = false

[urlhaus]
enabled = false
```

And to stop everything:

```bash
sudo rm /etc/cron.d/dirtyland-reporter
```

<b>If the ban comes.</b> abuse.ch allows appeals. What works is explaining plainly what the machine is, what caused the violation and what has been changed so it does not happen again.

## 3.6 Making life easier for ourselves.

There are actions we are likely to end up doing many times:
- Logging into the decoy to see how it behaves.
- Stopping everything when something goes wrong.
- Etc.

Since we do not want to force anyone to learn commands or open this documentation.<br>
I decided to create these scripts, which bring together all the possible actions I have been able to carry out on the server:

| Script | What for |
|---|---|
| `acceder_ssh_para_vagos.sh` | Log into the decoy from inside the VPS itself |
| `boton_del_panico.sh` | Stop both containers dead, and bring them back |
| `cortar_el_grifo.py` | Switch off publishing to a specific platform, and cron's mode |
| `estoy_dentro.py` | Silence the host's alerts while you are working on the machine |
| `que_pasa_con_las_plataformas.py` | Platform by platform: what was published, what was discarded and **why** |
| `voy_al_dia.py` | Which version the VPS has in place and whether it matches the repository's copy |
| `que_le_falta_al_senuelo.py` | Which binaries the decoy **claims to have** and cannot run, ordered by what the bots have actually typed |
| `banco_shell_real.py` | Runs lines through the **real shell**, Cowrie's protocol over its `fs.pickle`, and compares with what `bash` answers. No network and no touching the VPS. It covers what the command tests cannot see: the tokenising, the redirection, the parentheses and the current directory. **403 cases green**, and the open ones go on a separate list |

These files are in the repository's `3.6 Para facilitarnos la vida/` folder.<br>
We copy them:

```bash
install -m 700 -t ~/ "/tmp/dirtyland-repo/3.6 Para facilitarnos la vida/"*.sh "/tmp/dirtyland-repo/3.6 Para facilitarnos la vida/"*.py
```

A wildcard and not the list of names, so that adding a script to that folder does not mean touching this step. The `tests/` do not come along, because the wildcard does not descend into subdirectories. And it is `700` because one of these scripts shuts down the whole decoy and another touches `config.ini`.

```bash
ls -l ~/*.sh ~/*.py
```

All nine must show up as `-rwx------`: the eight in the table and `que_hizo_esta_ip.py`, which is used in 3.9.

### 3.6.1 A short explanation of how each command works.

#### Logging into the decoy.

With no arguments it logs in as `alyosha`; another `userdb` user can be passed:

```bash
~/acceder_ssh_para_vagos.sh
```

```bash
~/acceder_ssh_para_vagos.sh admin
```

It does not ask for the password, it types it itself. To test a <b>failed</b> login, for example to see whether the alert fires, you ask it to prompt:

```bash
~/acceder_ssh_para_vagos.sh admin --pedir
```

It connects to the container <b>from inside the VPS</b>, so the session is not mistaken for an attack. It needs OpenSSH 8.4 or later.

#### The panic button.

It stops both containers, and with them all incoming activity. It needs `sudo` and asks for confirmation by typing `PARAR`:

```bash
sudo ~/boton_del_panico.sh
```

```bash
sudo ~/boton_del_panico.sh --estado
```

```bash
sudo ~/boton_del_panico.sh --reanudar
```

It does not touch the firewall, it deletes nothing, and the reporter keeps processing what has already been collected.

#### Cutting off a platform's tap.

It stops publishing to a specific platform while you sort out a question about it. It needs `sudo`, because it edits `config.ini`:

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

You toggle by number, and several can be given (`0 1`). Before confirming it shows what is going to happen and leaves a dated copy of `config.ini`. <b>Option 0 is cron's mode</b> and overrides everything else: with it in simulation, nothing is published. Only <b>publishing</b> is switched off: the decoy keeps capturing and the reporter keeps collecting.

A 🟡 `PARTIAL` state is resolved by <b>switching off</b>, not on:

| Current state | On choosing it |
|---|---|
| 🟢 all three on | all three are switched off |
| 🟡 some on | all three are switched off |
| 🔴 none on | all three are switched on |

To just look, without changing anything:

```bash
sudo ~/cortar_el_grifo.py --estado
```

#### Silencing the alerts while you are inside.

When you yourself log into the machine, everything you do fires alerts. This silences them. It needs `sudo`, because it writes into `/opt/dirtyland/monitor/`:

```bash
sudo ~/estoy_dentro.py
```

```bash
sudo ~/estoy_dentro.py --estado
```

| What it silences | What it does **not** silence |
|---|---|
| Everything going through `send-alert.sh`: the SSH watcher, the command one, the firewall one and Dionaea's. That is, the host's monitoring | The **daily summary**, which is sent with `--siempre` on purpose |
| | The **decoy's** chat: they are two bots and two separate conversations (section 3.4.2.7) |
| | The decoy itself. Cowrie and Dionaea carry on capturing, and the reporter carries on publishing. To stop them, there is `~/boton_del_panico.sh` |

By default it stays quiet for <b>4 hours</b> and switches itself back on. Silence with no time limit can be requested by typing `forever`. Silenced alerts are not lost: they are logged and the daily summary counts them.

```
Vigilancia del anfitrion
🔴 SILENCIADA --- vuelve sola en 143 min
  🟡 6 aviso(s) retenidos en /opt/dirtyland/monitor/silenciadas.log
```

#### Knowing whether what is in place is what is in the repository.

It needs `sudo`, because nearly everything deployed belongs to `root`:

```bash
sudo ~/voy_al_dia.py
```

<b>It must be run before exposing.</b> It compares the version in place on the VPS with that of the copy `git archive` left in `/tmp/dirtyland-repo`:

<pre>
en la maquina : 7f0e389  2026-08-28T06:50
en la copia   : 7f0e389  2026-08-28T06:50
AL DIA
</pre>

If they do not match it says `ATRASADO`, and the first time, with the machine not yet marked, `SIN MARCAR`. It changes nothing. It returns `0` if they match, `1` if the machine is behind or unmarked and `2` if it could not compare, for example because the folder was uploaded by hand instead of with `git archive`.

#### What the decoy claims to have and cannot run.

It needs `sudo`, because it reads `fs.pickle` and Cowrie's logs and queries the container:

```bash
sudo ~/que_le_falta_al_senuelo.py
```

The decoy's filesystem advertises hundreds of binaries it cannot run, and that is a contradiction that does not happen on any Linux:

<pre>
$ ls -la /usr/bin/sed   ->  -rwxr-xr-x 1 root root 126424 Jan  5 2023 /usr/bin/sed
$ file /usr/bin/sed     ->  ELF 64-bit LSB pie executable, x86-64
$ which sed             ->  /usr/bin/sed
$ sed --version         ->  -bash: /usr/bin/sed: No such file or directory
</pre>

The script sorts what is missing by what the bots have actually typed against this decoy, so it tells you what is worth emulating first:

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

- The first shows only the ranking of what is typed most, with a mark on what the decoy cannot run.
- The second also lists the ones nobody has ever typed.

#### Knowing whether you are up to date.

This is what lets `voy_al_dia.py` know next time which version is in place:

```bash
sudo ~/voy_al_dia.py --marcar
```

> [!IMPORTANT]
> <b>This is the last step of any deployment, and the only one you have to remember.</b> What it does not detect: if you copy some pieces and not others, it will say you are up to date all the same, because it only looks at the stamp.

#### Other scripts.

Yes, I have not included them all, because the three missing ones are in 3.9.

## 3.7 Final checks before exposing.

Since we are this paranoid and rigorous about our work, we need to confirm:

### 3.7.1 Both alert channels work.

If we expose the decoy and the alerts do not work, we will be missing out on precisely what we built all this for.

This is the quick check (that both bots talk). The full rehearsal, alert by alert, is in the next two sections.

The <b>host</b>'s bot:

```bash
sudo /opt/dirtyland/monitor/send-alert.sh "Comprobacion previa a la exposicion"
```

And the <b>decoy</b>'s bot, by triggering a real event from inside (the honeypot is still sealed, so we connect straight to the container on its internal IP):

```bash
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null alyosha@172.20.0.10
```

Once inside, any command should fire an alert to Cowrie's Telegram:

```bash
whoami
exit
```

### 3.7.1.1 The full rehearsal: the twenty-five alerts.

That both bots talk does not mean **every** alert arrives. Each one is composed by a different watcher, with its own HTML, its own flags and its own splitting, so a formatting fault in one says nothing about the others.

`probar-avisos.sh` fires them all, one after another. **Twenty-two are the host's** and it builds them with fake inputs; the **last three are the decoy's** and need a real session, so they go at the end and are explained a little further down:

```bash
sudo /opt/dirtyland/monitor/probar-avisos.sh
```

It takes about a minute (it waits three seconds between messages so as not to hit Telegram's limit) and it runs through these twenty-five, in this order:

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

The last three are the **decoy's**, and no host watcher composes them: the plugin that lives inside Cowrie does, and that one only speaks when there is a session. So those do not get their input faked (you genuinely log in, type and upload a file), and they arrive on the phone like this:

<pre>
[Cowrie vía SSH]     Event: cowrie.login.success
[Cowrie vía SSH]     ACTOR NUEVO / GUION NUEVO   (con los comandos, a los 30 s)
[Cowrie]             MUESTRA NUEVA  SHA256: e3b0c442...b855
[Cowrie vía Telnet]  Event: cowrie.login.success
</pre>

<b>Somewhat more than twenty-five messages</b> arrive on the phone, because there are steps that fire several and that is what would really happen: step 19 sends a "caído" for each relay plus the "SIN ACCESO" that summarises them, and step 4 sends a batch for each user who was typing.

If any of them does not appear, the one at fault is its watcher and it has to be looked at **before** exposing. The terminal says which one it is on, so the missing one identifies itself.

A `send-alert.sh hola` would only test the token. Here every alert is composed by the real code, with made-up data, so what arrives on the phone is exactly what will arrive the day it happens.

And it touches nothing in production. Every watcher accepts, through an environment variable, where its state is and where it reads from, and the rehearsal points them at a temporary directory that gets deleted on exit: no counter advances, no IP is left marked as alerted. The only one that runs against real data is the daily summary.

The relays are not hardcoded either: the proxy's six alerts come from reading `proxys.conf`, which is where the watcher reads them from, and the flag is deduced from the first two letters of the relay's name.

And if you only want to repeat one (because it failed, or because that watcher has just been touched), you ask for it by number:

```bash
sudo /opt/dirtyland/monitor/probar-avisos.sh --solo 14
```

> [!WARNING]
> <b>This one does leave a trace, unlike the previous twenty-two.</b> Those are built in a temporary directory and touch nothing; these are real sessions against the decoy, so they stay in Cowrie's database, in the command log and in `downloads/`, and they will show up later in the analysis report. That is why they go behind an option of their own.

Three details about this batch. The file uploaded is the <b>empty file</b>, whose SHA-256 is `e3b0c442...b855`: a real hash, harmless and present in VirusTotal, so the alert's link can be followed all the way. There are two downloads on purpose, because Dionaea only records the MD5 in its database and you need to see both forms of the message. And the rehearsal writes into Dionaea's database, so it leaves made-up rows that the next day's summary would count.

The "Block IP" button is tested separately, on the spot: it arrives inside the daily summary, you press it from the phone and it must answer `🚫 BLOCKED` in the same message. That walks the whole route, the plugin, the queue, the host's `sudo` and `nft`, and that press comes from your finger, so there is no script to rehearse it.

Two Cowrie alerts do not come out in this rehearsal, and it is not a matter of waiting longer: the automatic ban and the summary of what was suppressed cannot come from here, because the plugin inside the container composes them and they depend on accumulated real traffic. They are seen in 3.8.2, when there is somebody to provoke them.

Both arrive on their own once the decoy has been exposed for a while. If you do not want to wait for the ban's two hundred repetitions or for the summary's half hour, the thresholds are read from the environment and can be lowered for the first few days in the `docker-compose.yml`:

```
    environment:
      - TZ=Europe/Kyiv
      - AUTOBAN_REPETICIONES=20
      - DIGEST_INTERVAL=300
```

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml up -d cowrie
```

Once you have seen them, both lines get removed and the container is brought back up the same way. In production the right values are the factory ones.

### 3.7.2 The monitoring services are running.

```bash
sudo systemctl status dirtyland-sshwatch.service --no-pager
sudo systemctl status dirtyland-cmdwatch.service --no-pager
sudo systemctl status cron --no-pager
sudo crontab -l | grep -v -e '^#' -e '^$'
```
<i>I added a `grep -v` to remove the comments: if root's crontab was ever opened with `crontab -e`, it has a 23-line header.</i>

All three must show:
- `active (running)` and `enabled; preset: enabled`.
- And that the command log is in place: `/etc/profile.d/dirtyland-registro.sh` must exist with mode `644`, **and `grep -c dirtyland-registro /etc/bash.bashrc` must give `1`**. Without the first, `dirtyland-cmdwatch` runs watching an empty channel. Without the second, everything typed in a root shell opened with `sudo su` is lost.
- `sudo crontab -l` must show <b>five</b> lines. They go with `sudo` because that is where they were installed in 3.4.4: your own user's crontab is empty and a bare `crontab -l` answers "no crontab for user", which looks as if everything is missing when nothing is.

| Task | Line | If it is missing |
|---|---|---|
| Daily summary | `0 6 * * * /opt/dirtyland/monitor/daily-digest.sh` | |
| Dionaea watch | `*/5 * * * * /opt/dirtyland/monitor/dionaea-watch.sh` | Attacks over SMB, RPC and MSSQL are not notified: Dionaea has no alert plugin like Cowrie |
| Banned IPs | `0 6 * * * /opt/dirtyland/monitor/baneadas-diario.sh` | |
| Access proxies | `*/30 * * * * /opt/dirtyland/monitor/proxy-watch.sh` | The day Mullvad drops a relay you find out when you cannot get in |
| Country table | `0 4 1,16 * * /opt/dirtyland/geoip/generar-tabla-paises.py --avisar` | The alerts' flags fall out of date with nothing to say so |

### 3.7.3 The containers are up and healthy.

```bash
sudo docker ps
```

Both (`dirtyland_cowrie` and `dirtyland_dionaea`) must appear in the `Up` state, and neither in `Restarting` (which would indicate something failing in a loop).

We also check that Cowrie loaded its two output engines and that there are no filesystem loading errors:

```bash
sudo docker logs dirtyland_cowrie --tail 20
```

### 3.7.4 Knowing exactly what we are exposing.

This is the most important check of all: <b>what is listening, on which port and on which IP</b>.

```bash
sudo ss -tulnp
```

What has to come out, and nothing else:

| IP | Port | Service | Who it is |
|---|---|---|---|
| `[IP VPS]` | 22 | SSH | Cowrie (Linux decoy) |
| `[IP VPS]` | 23 | Telnet | Cowrie (Linux decoy) |
| `[IP VPS 2]` | 135 | RPC | Dionaea (Windows decoy) |
| `[IP VPS 2]` | 445 | SMB | Dionaea (Windows decoy) |
| `[IP VPS 2]` | 1433 | MSSQL | Dionaea (Windows decoy) |
| `0.0.0.0` | 56769 | SSH | <b>Our real administration</b> |

> [!WARNING]
> If <b>any other port</b> appears listening that is not on that list, you have to find out what it is before exposing anything.

Because this is a VPS, an extra port appears: <b>5355</b>, TCP and UDP, which is `systemd-resolved`'s LLMNR. It listens on every interface, but the firewall does not let it in from outside and it is local network discovery traffic, not a service of ours.

`ss`'s listing shows what is listening on the <b>host</b>. The decoys' ports (22 and 23 on Cowrie; 135, 445 and 1433 on Dionaea) do not appear there, because with `"userland-proxy": false` there is no process occupying them: they are resolved with DNAT, and they get checked in the `nat` table in the next section.

### 3.7.5 The definitive docker-compose.

The file does not get written again here: it gets **checked**. It came from part 1 of the repository and its `volumes` block was generated by 3.4.2.9's script, so what is called for is confirming that what is mounted is what should be.

First, that the syntax is valid:

```bash
cd /opt/dirtyland && sudo docker compose config >/dev/null && echo "compose OK"
```

What has to be looked at are the three things that may have been left behind. **Which ports it publishes**:

```bash
cd /opt/dirtyland && sudo docker compose config --format json | python3 -c "import json,sys; [print(f\"{s}: {[p['published'] for p in v.get('ports',[])]}\") for s,v in json.load(sys.stdin)['services'].items()]"
```

<pre>
cowrie: ['22', '23']
dionaea: ['445', '135', '1433']
</pre>

If `23` does not appear under `cowrie`, the decoy offers telnet internally but nobody can reach it, and no log says so (see point 4 of section 3.4.2.10).

**How many command modules it mounts**, which have to match the ones in `cmdpatch`:

```bash
echo "en cmdpatch: $(ls /opt/dirtyland/cowrie/cmdpatch/*.py | wc -l)   montados: $(sudo grep -c 'cmdpatch/.*\.py:' /opt/dirtyland/docker-compose.yml)"
```

The two numbers have to be equal. If the second is smaller, there is a command that exists on the host and that the container is not using: it is corrected by launching 3.4.2.9's generator again with `--apply`, not by editing the file by hand.

**And that the time zone goes in twice**, the variable and the mount:

```bash
sudo grep -E 'TZ=|/etc/localtime' /opt/dirtyland/docker-compose.yml
```

<pre>
      - TZ=Europe/Kyiv
      - /etc/localtime:/etc/localtime:ro
</pre>

### 3.7.6 The firewall rules are still intact.

```bash
sudo nft list ruleset
```

The `packets` and `bytes` counters change on every query; what matters is the <b>structure</b>. More tables come out than we wrote ourselves, because Docker creates its own at startup, and that is normal.

- <b>`table ip nat`, `DOCKER` chain.</b> The DNAT, with each decoy tied to its IP: `[IP VPS]` to `172.20.0.10` and `[IP VPS 2]` to `172.20.0.20`. It already works.
- <b>`table ip filter`, `DOCKER` chain.</b> Docker already accepts the inbound traffic to the five ports. As far as it is concerned, the decoys would be reachable.
- <b>`table inet filter`, `forward` chain.</b> Ours, at `policy drop` and with no inbound rules. Both tables are evaluated, so it is enough for one to discard the packet: Docker says yes, we say no, and the no wins.
- <b>`table ip raw`.</b> It discards traffic aimed at `172.20.0.10` and `172.20.0.20` that does not come through the bridge, so that nobody can dodge the DNAT.

That is the piece section <b>3.8.2</b> changes: part 4 adds the missing inbound rules. Until then the decoy stays sealed.

The four tables above have to come out, with `inet filter`'s `forward` at `policy drop` and with no inbound rules.

And most importantly, that the firewall survives a reboot. To check that:

```bash
sudo systemctl is-enabled nftables
```

### 3.7.7 Final confirmation: we are still sealed.

The definitive test: trying to get in <b>from outside</b>, from a machine that is not the VPS.

```bash
IP1=[IP VPS]; IP2=[IP VPS 2]; for par in "$IP1 22" "$IP1 23" "$IP2 135" "$IP2 445" "$IP2 1433"; do nc -vz -w 3 $par; done
```

And the same from PowerShell, the command from 3.4.1:

```powershell
$ip1 = '[IP VPS]'; $ip2 = '[IP VPS 2]'; foreach ($prueba in @(@($ip1,22),@($ip1,23),@($ip2,135),@($ip2,445),@($ip2,1433))) { $h,$puerto = $prueba; $t = New-Object Net.Sockets.TcpClient; $abierto = $t.ConnectAsync($h,$puerto).Wait(3000); "{0,-16} {1,-6} {2}" -f $h, $puerto, $(if ($abierto) { 'ABIERTO' } else { 'cerrado o filtrado' }); $t.Close() }
```

All five have to give `timed out` (or `cerrado o filtrado`, if you did it from PowerShell). If any of them connected, we would already be exposed without knowing it.

> [!IMPORTANT]
> This test has to be done <b>twice</b>: once <b>with the administration VPN connected</b> (our Mullvad IP, the only one the firewall allows on port 56769) and once <b>with the VPN off</b> (simulating any attacker from the internet). In both cases the decoys' five ports must give `timed out`. The only legitimate exception is administration port 56769, which must <b>only</b> answer with the VPN connected and from our IP.

During the tests a `tcpdump` may show real inbound packets from automated scanners touching our IPs. That is the internet's background noise and it does not mean the decoy is exposed: the firewall is discarding them, which is precisely what is being checked.

### 3.7.8 The automatic reports are ready (but on hold).

We confirm that the reporter is installed and that its shield works, albeit still without API keys (they go in just before exposing):

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --self-test
```

It must exit with code 3 and complain only about the `api_key` entries, which are added in 3.8.1 (the blocklist covers our IPs, the barrier blocks what it should and lets through what it should). And that cron has it scheduled:

```bash
grep -r reporter /etc/cron.d/
```

The API keys are the <b>last</b> thing before exposing: while the decoy is still sealed, there is nothing to report. They are added to `config.ini` in 3.8.1.

### 3.7.9 One last recommendation before the final step.

Before exposing, it is worth taking a <b>snapshot</b> of the VPS from the provider's panel, if it happens to offer one. If something went wrong after the exposure, we could come back to this exact state (verified and sealed) without redoing the work.

> [!CAUTION]
> With all these checks passed, the next section is <b>real exposure to the internet</b>. From that moment on any attacker on the planet can reach our decoys, and both IPs' reputation starts being consumed. It is a deliberate step and, in that sense, an irreversible one.

### 3.7.10 The thirty-four suites, all at once.

Throughout the guide each section runs its own: Telegram's in 3.4.2.7 and the reporter's in 3.5.5.2. This is the complete run-through, **before exposing**, and it also serves for when something has been touched and you cannot remember which section it belonged to.

They need no keys, no network and no decoy running: they replace the HTTP calls with a double and work over temporary directories. They are run from the repository's tree, because some of them read the file they test by relative path:

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

And if all you want is the verdict, without going through all thirty-four:

```bash
cd /tmp/dirtyland-repo && fallos=0; total=0; while IFS= read -r -d '' t; do total=$((total+1)); case "$t" in *.py) python3 "$t" >/dev/null 2>&1 ;; *) bash "$t" >/dev/null 2>&1 ;; esac || fallos=$((fallos+1)); done < <(find . -path ./.git -prune -o \( -name 'test_*.py' -o -name 'test*.sh' \) -print0); echo "suites: $total   con fallos: $fallos"
```

<pre>
suites: 34   con fallos: 0
</pre>

What each one protects, so you know what has broken when one fails:

| Suite | What it watches |
|---|---|
| `test-acceder-ssh.sh` | That the access helper logs in **without typing anything**: the test's `ssh` is a mock and runs the real `SSH_ASKPASS`, so what gets checked is the password it receives, that the real `userdb` takes precedence over the script's copy, that the helper does not carry the secret inside it and that the secret does not stay on disk |
| `test_parche_protocol.py` | The terminal's password mode. It presses all eleven editing keys one by one inside a `[sudo] password for ...` and checks that **nothing reaches** the terminal (deletion used to eat the prompt, the arrows painted the history and `Ctrl-L` repainted the password in the clear) and that outside password mode they all carry on doing what they always did |
| `test_sanitize_pickle.py` | The filesystem's sanitiser: the cover story, the stock `/etc` files, telnet's coherence in both halves, the time zone, the links' targets, the `/etc/mtab` that pointed at the build container's PID and that same PID inside `/proc` |
| `test-vigilancia-host.sh` | The host's command log and the silencer: that a command with `pwd=` written inside it cannot choose which directory appears in the alert, that the silencer keeps quiet when it should and lets the daily summary through, and that an alert with no body still gets sent |
| `test_comandos.py` | The command modules and <b>the cover story's coherence across different files</b>: that `lsblk`, `df`, `/proc/mounts`, `/etc/fstab` and the canned `dmesg` describe the same disk, that the `dmesg` uses `/proc/version`'s kernel and `ifconfig`'s MAC, and that the canned outputs land in `usr/bin/` and not in `bin/`, which is where they do not fire |
| `test_gates.py` | The reporter's gates, one by one, MalwareBazaar's **two policy vetoes**, and that AbuseIPDB's reports tell the truth: the public port and not the internal one, and no category the evidence does not support |
| `test_end_to_end.py` | That in simulation not a single publication goes out to the network, and that a correct configuration passes `--self-test` |
| `test_botones_cowrie.py` | The bot's ban buttons and the transport labels (`vía SSH` / `vía Telnet`) and that the header does not carry the `sensor` again |
| `test_memoria_cowrie.py` | What the plugin remembers and what it reports. **The per-IP memory**, which decides when to go quiet: that a repeated script alerts once and not once per session, and that on trimming the memory it stops claiming nothing is new, because on an incomplete memory you cannot distinguish "it never did it" from "I forgot" |
| `test_repetidas_dionaea.py` | **The memory that stops Dionaea repeating the same alert every five minutes.** Both functions are extracted from the deployed script and run with a real `bash`, not rewritten in Python, since then the test would be checking something else |
| `test_telnet_opciones.py` | The telnet negotiation, the one that brought down every session |
| `test_que_hizo_esta_ip.py` | One IP's dossier, over a synthetic decoy with two IPs in the same log. Above all that <b>nobody else slips in</b>, because a dossier mixing two attackers is not a formatting error; it is a badly made report: it catches the three places where someone else could slip in, including a similar key that SQL's `LIKE` matches. And the two things the encryption depends on: that the tar does not open without the key and that no plaintext `.tar.gz` is left behind |
| `test_que_le_falta.py` | The census of what the decoy claims to have and cannot run. Above all that <b>an emulated command never comes out as missing</b>, which is what happened when reading the catalogue from `cmdpatch` rather than asking the container |
| `test_paises.py` | Each IP's little flag. Above all that it <b>cannot bring an alert down</b>: that a table that is missing, half written or unintelligible returns empty rather than blowing up, or worse, rather than returning any two characters that look like a country. Plus each range's boundaries, and that the table is sorted, which is what the binary search relies on |
| `test_cortar_el_grifo.py` | That toggling cron **always leaves a single active line**, in both directions |
| `test_que_pasa_con_las_plataformas.py` | The two day counters in the per-platform report, which are the ones looked at to know whether something is wrong: that they count today's and not the all-time total, that a simulation does not count as published, and that the reason they write is the real one and not a generic one |
| `test_voy_al_dia.py` | That the deployment comparator tells the truth in all three states and that it refuses to accept a copy brought over by hand, whose stamp arrives unsubstituted. And the three that watch that the README does not go stale: that the suite list is complete, that <b>every file the README says to copy genuinely exists</b> and that it still says to load the command log from `/etc/bash.bashrc` |
| `test-digest-modo.sh` | The daily summary's reporters section, entirely: that cron decides the colour, the four `[MOTIVO: ...]` lines, and that the counts are over 24 hours and not over the last fifteen-minute pass |
| `test-lib-telegram.sh` | The sending, the message splitting and the HTML escaping |
| `test-ssh-watch.sh` | The watcher for logins to the host |
| `test-breaker-watch.sh` | The abuse.ch account's circuit breaker |
| `test-cuota-watch.sh` | The daily quota watcher: that it warns when the allowance runs out and only then, that it does not repeat while it stays exhausted, that a change of day counts as a new transition, and that it looks at `api_calls` and not `quota`, because the first counts calls, which is what the limiter compares against |
| `test-proxy-watch.sh` | The SOCKS proxy watcher, with Mullvad's API simulated: that it warns when a relay goes down and when it comes back, that it keeps quiet while nothing changes, and that an odd API response does not leave it mute forever |
| `test-probar-avisos.sh` | The dry-run rehearsal of the host's twenty-two alerts from 3.7.1.1: that <b>all</b> of them still come out and with the header each watcher writes, so that if somebody renames an alert and does not touch the guide this turns red; that in a dry run nothing is sent to Telegram and no production state is touched; and that with a silence window open the rehearsal does not start |
| `test_analisis.py` | `ANALISIS/analisis.py`'s intelligence report over a <b>synthetic</b> backup, because real captures cannot be uploaded to the repository: that the scripts get grouped (twelve IPs with the same script are one actor, not twelve), that Cowrie's time is corrected the same way as in the collector, that what is unreadable is said rather than coming out as a zero, and that the report cannot end up in a commit |
| `test-enlaces-malware.sh` | The alerts' links to VirusTotal and MalwareBazaar |
| `test_parche_mssql.py` | Dionaea's loop that hung the decoy. It does not check that one piece of text is replaced by another: it **runs the loop**, before and after the patch, with the fragment copied letter by letter from the `mssql.py` of the digest-pinned image, and checks that one never finishes and the other does. And that the patch **refuses to apply itself** if that file changes |
| `test-montajes-dionaea.sh` | That adding a mount to the `docker-compose` does not bend the YAML, because a bent compose is still valid YAML and without that mount Dionaea hangs again on the first malformed MSSQL packet. There are two mock `docker`s, one that validates and one that always rejects, because a rollback that has never been tested is one you do not know exists |
| `test-dionaea-mudo.sh` | The "Dionaea alive but mute" watcher, the control that has already failed twice in one week: five days without recording a single connection while `docker ps` said `Up`, the process existed and the DNAT counted packets. It checks that the alert comes out **after 2 h**, not the next day. It needs the `sqlite3` binary |
| `test-registro-comandos.sh` | That what a person types on the host gets recorded, and above all the **coverage**: a root shell opened with `sudo su` recorded nothing (`/etc/profile.d` is only read by *login* shells, and with `sudo -i` it did work, so the fault depended on how you became root). It starts a real `bash` of each kind and types commands into it |
| `test_auditd_watch.py` | The reading of `auditd`'s log, against a **real sample** from the VPS and not one written by hand: the interpreted fields that run into the previous one with no space, the arguments in hexadecimal and an event spread across several lines joined by its serial number |
| `test-cron-dirtyland.sh` | That the periodic tasks get set **without `nano` and without duplicating**. This step was the only one in the deployment that was not copy and paste |
| `test-baneadas-diario.sh` | The listing of blocked IPs and where each ban came from, against the **real** shape of an `nft list set`: elements separated by commas, spread across several lines and each followed by its comment |
| `test-banear-dos-veces.sh` | Pressing an alert's ban button when its IP is already banned. `nftables` complains when adding an element that already exists and with `set -e` it brought the script down, so the button gave an error in a case that is not one: the result you were after is already there |

Two need the `sqlite3` binary (`test-dionaea-mudo.sh` and `test-digest-modo.sh`). On the VPS it is there; on another machine it has to be installed or those two skip themselves, saying so.

That all thirty-four are green **does not say the decoy is sound**: they say that the logic that can be tested without the internet behaves as expected. What the decoy looks like from outside is measured in 3.8.2.

### 3.7.11 Before formatting or moving the machine: what has to be saved.

Almost everything in this guide gets **regenerated**: the pickle, the honeyfs, the modules, the `docker-compose`, the firewall rules. All of that comes out of the repository and a `docker build`. But there are things that **do not get regenerated** because they are the result of having been listening, and those are lost with the disk.

> [!CAUTION]
> <b>The state database on its own is no use at all.</b> The `samples` table stores the **path** to the binary, not the binary. If you save `state.sqlite3` and not Docker's volumes, the queue of pending samples points at files that no longer exist. Both have to be saved.

What there is, and what gets lost with each thing:

| What | Where | What you lose if it goes |
|---|---|---|
| Reporter state | `/var/lib/dirtyland-reporter/state.sqlite3` | what has already been reported and uploaded, the **queue of samples awaiting a verdict**, the day's quotas, the circuit breaker and the rejections |
| **Cowrie's malware** | `dirtyland_cowrie-var` volume -> `_data/lib/cowrie/downloads` | the captured binaries |
| Session log | same volume -> `_data/log/cowrie/cowrie.json*` | the evidence of everything that has happened |
| **Dionaea's malware** | `dirtyland_dionaea-var` volume -> `_data/lib/dionaea/binaries` | the SMB binaries |
| Dionaea's events | same volume -> `dionaea.sqlite` | its record |
| The bot's memory | `/opt/dirtyland/Telegram Reports/state/` | the scripts already seen and the banned list |
| SSH host keys | `/opt/dirtyland/cowrie/keys/` | the decoy's **fingerprint**, which would change |
| Secrets | `config.ini`, `telegram.cfg`, `telegram.env` | the API keys and the tokens |
| Firewall rules | dump of `nft list ruleset` | **who ordered each ban**: automatic or by hand |

<b>1. Stop the stack.</b> With the databases writing, a hot copy can come out half done:

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml down
```

> [!WARNING]
> A bare `down`. **Never `down -v`**: that option deletes the named volumes, which is to say precisely the malware and the logs you are trying to save.

<b>2. Dump the firewall rules.</b> nftables rules live in the kernel, not in a file, so if they are not dumped they are lost when you format.

```bash
sudo sh -c 'nft list ruleset > /opt/dirtyland/monitor/nftables-ruleset.txt' && sudo chmod 600 /opt/dirtyland/monitor/nftables-ruleset.txt && sudo grep -c BANEADA /opt/dirtyland/monitor/nftables-ruleset.txt
```

That count is the number of banned IPs with a comment; if `0` comes out, the dump came out empty and there is no point going on.

> [!NOTE]
> **`sudo nft list ruleset > fichero` will not do**: the redirection is done by **your** shell, which is not root, so it tries to create the file without permissions, and in a root directory that fails. That is why it all goes inside `sudo sh -c '...'`.

<b>3. Pack it, compress it and encrypt it in one go, with a progress bar.</b> The volumes and the `/opt` paths go into the same archive, so the copy is a single thing and not three that have to be matched up afterwards.

The backup is several GB and `gzip` runs on a single core, so this takes a while. This script measures the total, shows the bar with its percentage and remaining time, uses `pigz` (parallel gzip) if it is there, and **leaves no unencrypted `.tar.gz` on the disk**. Paste it as is to create it:

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

And it is run:

```bash
bash ~/respaldo.sh
```

We check that what should be inside it is (by decrypting and listing, since a half-finished archive shows up here):

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -in ~/dirtyland-respaldo-*.tar.gz.enc -k 1234 | tar -tzf - | grep -cE 'downloads/|binaries/|state.sqlite3'
```

> [!CAUTION]
> The encryption with password "1234" is not after confidentiality; it is so that Windows Defender does not detect it (and if you use Linux it makes no difference). Windows Defender inspects any other archive, since it looks for and reads signatures/hashes.

`tar` is going to warn that a file changed while it was reading it, and that is normal: the decoy was listening until a moment ago and `cowrie.json` may have grown between `tar` opening it and finishing it. It exits with code 1, which is "warning", not "error": the archive is complete and can be restored.

<b>4. Bring the stack back up and fetch the encrypted file</b>, from your own machine and with the VPN up.

The backup is done, so <b>the decoy gets brought back up</b> so it does not spend any more time down (this only if you are NOT formatting right now; if you are about to format, skip it):

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml up -d
```

The script left the `.enc` in your own `home` and it is already yours, so you can download it directly. <b>From your machine</b> (works just the same in PowerShell and on Linux; `scp` uses the same `~/.ssh/config` from 3.2.6, so if a proxy relay is down you switch to one of the backup aliases):

```bash
scp dirtyland:~/dirtyland-respaldo-*.tar.gz.enc .
```

Once you have it downloaded, the copy in `home` gets deleted so as not to leave the malware (encrypted though it is) within the normal user's reach. <b>On the VPS</b>:

```bash
shred -u ~/dirtyland-respaldo-*.tar.gz.enc && echo "copia borrada de la VPS"
```

<b>5. When restoring</b>, on the new machine: follow the guide until the stack has been up once (so that Docker creates the volumes with their names) and **then** stop it, restore on top and bring it back up:

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml down
```

It gets decrypted and extracted in a single pipeline (the encrypted file is uploaded to the new machine first, for example to `~`):

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -in ~/dirtyland-respaldo-FECHA.tar.gz.enc -k 1234 | sudo tar -xzf - -C /
```

```bash
sudo docker compose -f /opt/dirtyland/docker-compose.yml up -d
```

And the first thing to look at afterwards, because it is what says whether the queue survived:

```bash
sudo python3 -c "import sqlite3
for r in sqlite3.connect('/var/lib/dirtyland-reporter/state.sqlite3').execute('SELECT state, COUNT(*) FROM samples GROUP BY state'): print(r[0], r[1])"
```

If you decide **not to restore** and to start from scratch, nothing terrible happens, but it implies this: the IPs already reported would be reported again, and the samples already uploaded would be retried only for the platforms to reject them as duplicates. It is not a ban, but it is avoidable noise.

## 3.8 Exposure.

Up to here all the work has been done with the decoy sealed. This section is the one that opens it to the internet, and it is only two steps: setting the API keys and applying part 4 of the firewall. In that order, because the keys carry no risk with the machine closed, whereas the firewall is the point of no return.

> [!CAUTION]
> From 3.8.2 onwards anyone can reach both decoys. Both IPs' reputation starts being consumed and the automatic reporting starts having material to talk about. If anything was left unverified in 3.7, you have to go back now.

### 3.8.1 The reports' API keys.

This is the last change to the reporter's configuration, and the one outstanding since 3.5.5.1:

```bash
sudo nano /opt/dirtyland/platform-reporter/config.ini
```

They are all together in `[api_keys]`, at the start of the file, and it is the <b>only</b> thing left to fill in. The three placeholders get replaced with the real keys:

```ini
[api_keys]
virustotal = <CLAVE-API-VIRUSTOTAL>
abusech    = <CLAVE-API-ABUSECH>
abuseipdb  = <CLAVE-API-ABUSEIPDB>
```

Three keys and not five: <b>MalwareBazaar, ThreatFox and URLhaus are the same abuse.ch account</b> and share an Auth-Key. It is the same reason 3.5.5.4's circuit breaker counts rejections per account and not per platform. Having them together and at the start has an advantage: to know what secrets this file contains, looking at that section is enough. And if some platform ever needed an account of its own, its `api_key` goes in its section and that one takes precedence over this one.

The file has to remain unreadable to anyone who is not `root`, because from now on it contains secrets:

```bash
sudo stat -c '%a %U:%G %n' /opt/dirtyland/platform-reporter/config.ini
```

It must answer exactly `600 root:root`. If it does not, the reporter will refuse to start, which is precisely what we want it to do.

Now the self-test has to come out clean for the first time:

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --self-test
```

It must finish with `self-test: todo correcto` and with code 0. If it is still complaining about some `api_key`, that placeholder was not substituted properly.

And a pass in simulation, which now does exercise the keys:

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini
```

This is the first moment the reporter talks to the platforms. With the keys in place, the simulation **does** make the read queries; what it does not do, and will not until 3.8.3, is publish. If a key were wrong, it would show up here as a `401` in the log, and it is better to find out now than with real traffic on top.

### 3.8.2 Final firewall: exposing.

This is the irreversible step. First of all, a backup of what is there:

```bash
sudo cp /etc/nftables.conf /etc/nftables_3.8.2.pre.exposicion___$(date +%Y-%m-%d_%H:%M:%S).conf.bak
```

> [!WARNING]
> Open **a second SSH session** now and leave it connected while you do this. If something went wrong with the `input` chain, that open session is what lets you fix it; with a single session and `policy drop`, one mistake locks you out of the machine.

Part 4's rule is in the repository's `CORTAFUEGOS` folder, just like the previous three:

```bash
sudo truncate -s 0 /etc/nftables.conf
```

```bash
sudo nano /etc/nftables.conf
```

The contents of **[CORTAFUEGOS/nftables-PART-4.txt](CORTAFUEGOS/nftables-PART-4.txt)** get pasted inside and reviewed:

```bash
cat /etc/nftables.conf
```

Four things change compared with part 3:

| Change | Why |
|---|---|
| An <b>ingress</b> block in `forward` | It is the only thing that exposes anything. Until now that chain's `policy drop` killed the traffic arriving by DNAT |
| <b>Container to container</b> forbidden | If Cowrie falls, it must not be able to touch Dionaea's 445. Without this line, the ingress rules themselves would allow it |
| The <b>second public IP</b> in the anti-pivoting | Part 3 only protected `[IP VPS]`. A compromised container could reach `[IP VPS 2]` |
| Out goes `input`'s `tcp dport 22 accept` | It never did anything, as 3.4.1 already explained, and reading it was misleading |

The ingress block's ports are the <b>container's</b> (Cowrie's 2222 and 2223, Dionaea's 135/445/1433), not the published ones. By the time the packet reaches `forward`, the DNAT has already rewritten the destination: that is why neither 22 nor 23 is visible there.

The syntax gets checked **before** applying anything:

```bash
sudo nft -c -f /etc/nftables.conf
```

That command must print absolutely nothing. If it prints something, it is a syntax error and the live firewall has not been touched yet. Only then is it applied:

```bash
sudo nft -f /etc/nftables.conf
```

And we verify what has ended up loaded:

```bash
sudo nft list chain inet filter forward
```

Now, **from your own machine, not from the VPS** and **with the administration VPN connected**, the five ports must answer. They are the same commands as in 3.7.7, but with the opposite result: there they had to time out, here they have to connect.

| Command | What has to come out |
|---|---|
| `nc -vz -w 3 [IP VPS] 22` | `Connection to [IP VPS] 22 port [tcp/ssh] succeeded!` |
| `nc -vz -w 3 [IP VPS] 23` | `Connection to [IP VPS] 23 port [tcp/telnet] succeeded!` |
| `nc -vz -w 3 [IP VPS 2] 135` | `Connection to [IP VPS 2] 135 port [tcp/epmap] succeeded!` |
| `nc -vz -w 3 [IP VPS 2] 445` | `nc: connect to [IP VPS 2] port 445 (tcp) timed out: Operation now in progress` |
| `nc -vz -w 3 [IP VPS 2] 1433` | `Connection to [IP VPS 2] 1433 port [tcp/ms-sql-s] succeeded!` |

And on Windows, all five at once. They all have to come out `ABIERTO` except 445, for the reason explained just below:

```powershell
$ip1 = '[IP VPS]'; $ip2 = '[IP VPS 2]'; foreach ($prueba in @(@($ip1,22),@($ip1,23),@($ip2,135),@($ip2,445),@($ip2,1433))) { $h,$puerto = $prueba; $t = New-Object Net.Sockets.TcpClient; $abierto = $t.ConnectAsync($h,$puerto).Wait(3000); "{0,-16} {1,-6} {2}" -f $h, $puerto, $(if ($abierto) { 'ABIERTO' } else { 'cerrado o filtrado' }); $t.Close() }
```

<b>That 445 fails from your machine is expected, and it is not the VPS's fault.</b> Outbound TCP/445 is blocked by nearly every VPN and nearly every domestic ISP, ever since the SMB worms, so the packet dies before leaving your network. That it says `timed out` and not `connection refused` is precisely the signal: a rejection is sent by the destination, a silence is swallowed by somebody along the way.

What remains is ruling out the other cause, which would be serious: that the VPS provider blocks it <b>on the way in</b>, because 445 is where Dionaea gets most of its samples. Dionaea is asked who has arrived, and this does not depend on your network:

```bash
sudo python3 -c "import sqlite3; d=sqlite3.connect('/var/lib/docker/volumes/dirtyland_dionaea-var/_data/lib/dionaea/dionaea.sqlite'); [print(f'  puerto {p:<6} {c:>6} conexiones   {i:>5} IPs distintas') for p,c,i in d.execute(\"SELECT local_port, COUNT(*), COUNT(DISTINCT remote_host) FROM connections WHERE connection_type='accept' GROUP BY local_port ORDER BY local_port\")]"
```

<pre>
  puerto 135         7 conexiones       2 IPs distintas
  puerto 445         7 conexiones       1 IPs distintas
  puerto 1433        8 conexiones       3 IPs distintas
</pre>

If 445 is accumulating connections, it is open to the internet and the block is only yours. If it stays at zero while the other two climb, the provider is blocking it and you have to write to them. Give it a few hours: freshly started, the sample is very short.

And there is one last check, and all the reporting depends on it. After those connections from outside, the IP recorded has to be yours, not Docker's gateway:

```bash
sudo grep -o '"src_ip": *"[^"]*"' /var/lib/docker/volumes/dirtyland_cowrie-var/_data/log/cowrie/cowrie.json | sort | uniq -c | sort -rn | head
```

Your VPN's exit node must appear. If everything still comes out as `172.20.0.1`, Docker is masquerading the source and **nothing will ever be reported about anyone**: the barrier would discard every attacker for not being a global address, without raising a single error. The reporter warns about it in the log, but it is better to see it here.

### 3.8.3 Switching the reporting to live mode.

> [!IMPORTANT]
> **FROM HERE ON IT REPORTS FOR REAL.** Everything before this was simulation: the reporter read, decided and wrote into the log what it *would have* sent, <b>publishing nothing</b>. The only traffic that went out to the network was read queries, because without them the decision gates could not be validated, which is precisely what you want to be looking at over these days. Here the brake comes off, and from cron's first pass onwards <b>it publishes</b> on all five platforms.
>
> **WHAT IS PUBLISHED IS PUBLIC AND PERMANENT, AND IT CANNOT BE WITHDRAWN.** A comment on VirusTotal or a report on AbuseIPDB is going to be read by people, and they accuse an IP that belongs to somebody. That is why the order matters: first you read a few days of simulation, and only when it convinces you do you change cron's line.

Cron is still in simulation, and it should stay that way for a few days. The place to look is the log:

```bash
sudo tail -n 60 /var/log/dirtyland-reporter/reporter.log
```

Or `tail -f` if you would rather watch it live, remembering that that one stays open until you press `Ctrl+C`.

What you are looking for there is that what *would have* been sent is reasonable: real attackers' IPs, none of ours, and the samples waiting for a verdict rather than being published while still hot. And the rejections, with their reason:

```bash
sudo python3 /opt/dirtyland/platform-reporter/orchestrator.py -c /opt/dirtyland/platform-reporter/config.ini --show-rejections 30
```

When the result convinces you, and not before, cron's line gets changed. It is done with this command and not with an editor because by hand one leaves **both** lines active or **neither**.

```bash
sudo sed -i -E 's|^(\*/15 .*malware-watch\.sh)$|#\1|; s|^#(\*/15 .*malware-watch\.sh --live)$|\1|' /etc/cron.d/dirtyland-reporter
```

And it is confirmed that **one single** line was left active, with `--live`:

```bash
grep -vE '^\s*(#|$)' /etc/cron.d/dirtyland-reporter | grep malware-watch
```

<pre>
*/15 * * * * root /opt/dirtyland/platform-reporter/malware-watch.sh --live
</pre>

> [!CAUTION]
> This is the step that starts publishing.

## 3.9 The end.

Once we have deployed the honeypot, waited as long as we wanted to wait and have a good harvest of findings, be they binaries, IPs and so on, it is time to document what we got.

Luckily, there are 3 scripts that are going to help us.

### 3.9.1 Analisis.py

This script:
- Extracts all the findings from all the IPs.
- Generates a very detailed and carefully made `.html` report that will help us analyse what happened in the honeypot.

To use it:

```bash
mkdir -p ~/datos-analisis && ln -sfn /var/lib/docker/volumes/dirtyland_cowrie-var /var/lib/docker/volumes/dirtyland_dionaea-var /var/lib/dirtyland-reporter "/opt/dirtyland/Telegram Reports/state" /opt/dirtyland/monitor ~/datos-analisis/ && sudo python3 /tmp/dirtyland-repo/ANALISIS/analisis.py --respaldo ~/datos-analisis --salida ~/analisis-senuelo-$(date +%F).html --ip-vps $(hostname -I) && sudo chown $USER: ~/analisis-senuelo-*.html
```

To get the encrypted findings off the VPS machine. The password is 1234, and remember that we encrypt them so that Windows Defender does not go off.

```bash
scp "dirtyland:~/dirtyland-respaldo-*.tar.gz.enc" .
```

To get the generated report, which is on the VPS machine.

```bash
scp "dirtyland:~/analisis-senuelo-*.html" .
```

### 3.9.2 Just one IP

This script was designed with the idea of:
- Taking the findings of a single IP.
- Having the best possible detail, for a single IP, on what it has done or not.
- The analysis it generates is a .txt that includes every command that IP has run, so you can take all of that, paste it into Claude, and if there is any command this honeypot does not handle, pass it on and let Claude work on it.

This is how you run it:

```bash
sudo ~/que_hizo_esta_ip.py <IP>
```

We are not going to explain how it works, because the script itself already explains in great detail how to use it.

To get the finding off the machine.<br>
<b>On Linux:</b>

```bash
scp 'dirtyland:~/ficha-*' "$(xdg-user-dir DESKTOP)"
```

<b>On Windows:</b>

```powershell
scp "dirtyland:~/ficha-*" ([Environment]::GetFolderPath('Desktop'))
```

And we will have it on the desktop.

### 3.9.3 the one for getting things out.

This script simply gets the findings out, and that is it.<br>
To use it:

```bash
bash ~/respaldo.sh
```

To get the finding off the machine.<br>
<b>On Linux:</b>

```bash
scp 'dirtyland:~/dirtyland-respaldo-*.tar.gz.enc' "$(xdg-user-dir DESKTOP)"
```

<b>On Windows:</b>

```powershell
scp "dirtyland:~/dirtyland-respaldo-*.tar.gz.enc" ([Environment]::GetFolderPath('Desktop'))
```
