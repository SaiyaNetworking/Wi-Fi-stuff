Wifi common issues (playbook in development)

PURPOSE
===========================================

The purpose of this playbook is both for reference material learned studying the Certified Wireless Network Administration (CWNA) certification 
given by the Certified Wireless Network Professionals (CWNP) organization and to serve as a reference guide for people unfamiliar with 
troubleshooting Wi-Fi issues. A fair amount of this has been built from both from experience and end-user tickets.

Note: While home users and power users can benefit from this playbook, this is primarily written for a business environment. Assumptions 
will be made that the reader will have a basic knowledge of networking concepts such as:
* OSI model (TCP/IP model is too broad for Wi-Fi)
* Physical/Layer 1 concepts
* Data Link Layer 2 concepts
* How packets route in a network

More technical concepts such as packet parsing, PLCP and PMD Layer 1 sublayers, MAC and LLC Layer 2 sublayers will generally be omitted/simplified for brevity's sake. 
A more in-depth analysis would require technical expertise and dedicated equipment.

# Table of Contents

1. **Basic Definitions**
   
   1.1 Network Devices  
   1.2 Network Standards & Frequency Bands  
   1.3 Common Wireless Terms  
   1.4 Security  
   1.5 Misc  

3. **802.11 Standards**

4. **Wi‑Fi 7 Technologies**

5. **Layers 1–7 Troubleshooting**
   
   4.1 Layer 1 – Physical  
      4.1.1 What is the Signal Strength?  
      4.1.2 Co‑Channel Interference (CCI)  
      4.1.3 Signal‑to‑Noise Ratio (SNR)  
      4.1.4 Walls (Signal Interference)  
      4.1.5 AP Placement (Signal Interference)  
      4.1.6 Obstructions (Signal Interference)  
      4.1.7 Radio Interference (RF)  
      4.1.8 AP Limitations  
      4.1.9 Airtime Contention  
      4.1.10 802.11 Standards (Impact on Quality)  
      4.1.11 Wi‑Fi Bandwidth  
      4.1.12 Lesser‑Known Problems & Miscellaneous Issues  

   4.2 Layer 2 – MAC Layer  
      4.2.1 Layer 1 Interference  
      4.2.2 Hidden Nodes  
      4.2.3 Mismatched Power  
      4.2.4 Security Verification Issues  
      4.2.5 802.1X / EAP (WPA2‑Enterprise)  
      4.2.6 Roaming Issues  
      4.2.7 Channel Utilization  

   4.3 Layer 3 – IP  

   4.7 Layer 7 – Application  

**Voice Wi‑Fi (Work in Progress)**


# 1. BASIC DEFINITIONS

## 1.1 NETWORK DEVICES

- **Access Point (AP):** Provides Wi‑Fi connectivity and bridges wireless clients to a wired LAN.
- **Gateway:** Device that connects an internal network to external networks outside the facility. Normally the "internet/WAN node".
- **Mesh Node:** AP that participates in a wireless mesh system, relaying traffic to other nodes wirelessly.
- **PD:** Powered Device. Device that uses PoE from either a switch or an injector.
- **PoE:** Power over Ethernet. Power used to power on certain devices such as phones and APs.
- **PoE Budget:** Total wattage a wireless deployment needs per switch.
- **PoE Injector:** A separate device that injects PoE to an ethernet cable adapter. Requires an external source of power such as an electrical outlet.
- **PSE:** Power-Sourcing Equipment. These can either be a PoE switch or a PoE injector.
- **Repeater / Extender:** Consumer device that rebroadcasts the current Wi‑Fi signals to extend range in exchange for efficiency.
- **Router:** Routes traffic between networks. SOHO/personal routers normally have an integrated wireless Access Point.
- **Switch:** Forwards Ethernet frames within a LAN; is the network backbone for APs.
- **WLC:** Wireless LAN Controller. Used as a centralized controller for a deployment of APs.
- **Wireless USB Adapter:** Adds Wi‑Fi capability to a computer via USB.



## 1.2 NETWORK STANDARDS & FREQUENCY BANDS

- **802.3 (Ethernet):** Wired LAN standard defining Ethernet physical and data‑link layers.
- **802.11 (Wi‑Fi):** Wireless LAN standards (a/b/g/n/ac/ax/be).
- **2.4 GHz Band:** Long range, low throughput, high interference. Only 11 20 MHz channels.
- **5 GHz Band:** Higher throughput, shorter range, more channels. Up to 25 20 MHz channels.
- **6 GHz Band (Wi‑Fi 6E/7):** Very high throughput, low interference, shortest range. Up to 50 20 MHz channels.
- **Channel Width:** Size of a Wi‑Fi channel (20/40/80/160/320 MHz); wider = faster but more interference and fewer channels.



## 1.3 COMMON WIRELESS TERMS

- **Airtime Contention:** The contention space all wireless devices fight for.
- **Association / Reassociation:** Processes for joining or roaming between APs.
- **Attenuate:** Reduction in strength, power, or amplitude of a radio signal as it travels from a router to a device.
- **Backbone (wired):** Ethernet cabling connecting APs.
- **Backhaul (wireless):** AP‑to‑AP communication over Wi‑Fi.
- **Beacon Frame:** AP broadcast announcing wireless network parameters.
- **BSS (Basic Service Set):** One AP and its associated clients.
- **BSSID:** MAC address of the AP radio; unique identifier for a BSS.
- **CAPWAP:** Control and Provisioning of Wireless Access Points. Uses a tunnel to allow a WLC to manage APs.
- **Cell:** The coverage area of an AP.
- **Channels:** Frequency slices used by Wi‑Fi radios.
- **CLIENT:** Client device.
- **Hidden SSID:** SSID not broadcast in beacons. Can still be discoverable through probing.
- **Interference:** Signal disruption from radio frequency (RF) sources.
- **ISP (Internet Service Provider):** Company providing internet access.
- **Latency:** Time for data to travel from source to destination.
- **MAC Randomization:** Client devices rotate MAC addresses for privacy.
- **Management Frame:** 802.11 management frames for coordinating 802.11 data. Can take up ~40–45% of airtime.
- **Mesh Networking:** APs wirelessly interconnect to extend coverage.
- **OUI (Organizationally Unique Identifier):** First 24 bits of a MAC address identifying the vendor.
- **Probe Request / Response:** Frames used for network discovery.
- **Roaming:** Client movement between APs while maintaining connectivity.
- **RSSI (Received Signal Strength Indicator):** Signal strength measurement at the client. Determines connection quality.
- **SSID (Service Set Identifier):** The broadcast network name.
- **STA:** Station. Interchangeably used with client device.
- **Throughput:** Data transfer rate.
- **Wireless:** Communication using 802.11-defined radio waves instead of cables.

## 1.4 SECURITY 

- **802.1X:** Authentication protocol that typically uses a RADIUS or TACACS+ server.
- **CA:** Certificate Authority. A trusted entity that hands out digital certificates.
- **Captive Portal:** Login or splash page before granting internet access.
- **Evil Twin:** Rogue AP mimicking a legitimate SSID.
- **Open Authentication:** Passwordless SSID. Normally used as courtesy Wi‑Fi for customers.
- **PSK (Pre‑Shared Key):** Basic password authentication used in WPA2/WPA3‑Personal networks.
- **RADIUS:** Remote Authentication Dial-In User Service. A service that uses 802.1X authentication.
- **Shared Key:** Deprecated security protocol.
- **TACACS+:** Terminal Access Controller Access-Control System Plus. Cisco‑proprietary centralized validation protocol.
- **WEP:** Deprecated security protocol.
- **WPA2:** Older Wi‑Fi security standard. Uses 4‑way handshake with AES‑CCMP.
- **WPA3:** Modern Wi‑Fi security standard. Uses SAE with AES‑GCMP.

## 1.5 MISC

- **Band Steering:** AP feature nudging clients to use 5 GHz or 6 GHz bands over 2.4 GHz.
- **CTS:** Clear to Send. Option with RTS to reserve transmission times by informing all clients to refrain from transmitting.
- **DFS Channels:** 5 GHz channels shared with radar; require dynamic frequency selection.
- **Load Balancing:** Distributing clients across APs.
- **RTS:** Request to Send. Option with CTS to reserve transmission times by informing all stations that a transmission is about to occur.


# 2. 802.11 STANDARDS

This is to be used as a basic checklist for any current devices and what new technologies are supported or unsupported.


802.11 legacy - 2.4 GHz FHSS/DSSS. Datarates are 2 and 1 Mbps. Practically ancient.
- PS (Power Save) Poll is used here
802.11b - 2.4 GHz DSSS. Datarates are 11, 5.5, 2 and 1 Mbps.
- WEP popularized (now obsolete)
- WPA introduced later (802.11i) for 802.11b and 802.11g
802.11a - 5 GHz OFDM. Datarates are 54, 48, 36, 24, 18, 12, 9, and 6 Mbps.
  
802.11g - 2.4 GHz OFDM (DSSS for backwards-compatibility.) Datarates are 54, 48, 36, 24, 18, 12, 9, and 6 Mbps.

802.11n - 2.4/5 GHz HT OFDM introduced. Datarates up to theoretical 600 Mbps. Realistic speeds ~40-150 Mbps.
- HT (High Throughput) frames introduced
- MIMO introduced
- Channel bonding for 40 Mhz
- Spatial multiplexing
- SM-PS (spatial multiplexing - Power Save) is introduced, replacing PS Poll
- Dualband
- Frame aggregation using A-MPDU and A-MSDU
- 64-QAM

802.11ac - 5 GHz VHT-OFDM. Datarates up to a theoretical 6.93 Gbps. Realistic speeds of 200-600 Mbps.
- Wi-Fi 5
- VHT (Very High Throughput) frames introduced
- Larger channel bonding for 80 Mhz and 160 Mhz
- MU-MIMO with up to 8 spatial streams
- Beamforming
- 256-QAM

802.11ax - 2.4/5/6 Ghz HE OFDMA. Datarates up to a theoretical 14 Gbps. Realistic speeds of 200 Mbps - 1.2 Gbps depending on frequency band.
- Wi-Fi 6 and Wi-Fi 6e
    - Wi-Fi 6e introduced the 6 GHz band
    - 1,200 MHz of new frequency space
    - Double the channel bonding
- HE (High Efficiency) frames introduced
- Channel subdivision (tones and resource units) introduced
- Trigger frames introduced
- BSS coloring and Spatial Reuse Operation introduced (less 2.4 GHz overhead)
- TWT (Target Wake Time) introduced for more efficient client sleep times
- WPA3 with SAE is introduced
- 1024-QAM

802.11be - 2.4/5/6 GHz EHT. Datarates up to a theoretical 46 Gbps. Realistic speeds of 1-5 Gbps (as of today)
- Wi-Fi 7
- MLO is introduced
- Preamble puncturing is introduced
- 320 Mhz bands are introduced
- 4096 QAM




# 3. WI‑FI 7 TECHNOLOGIES

Wi-Fi 7 is the new standard making its rounds with more of its design features fleshed out in the 802.11be standard. A lot of this is still in the immaturity phase with MLO and 
firmware support but it has shown exceptional results with deployments in both high-density (HD) and very high-density (VHD) environments. Analysis has shown that SNR can be upwards of 40-45, 
resulting in an extremely clean environment where there the biggest source of interference, cross-channel interference (CCI), is reduced by an extremely significant amount.

As of this current writing in March 2026, Wi-Fi 7 isn't widely adopted and will probably take upwards of a decade to be fully integrated in everyday use. This is because it both costs 
major money to update your infrastructure (especially when things "already work") and even though vendors are deploying devices that support 6ghz and the surrounding technologies 
for Wi-Fi 7, older devices will not be able to participate in the 6ghz band. A functional upgrade would require both the infrastructure and the end-user devices be upgraded to 
in order to fully utilize Wi-Fi 7. This would require a new fleet of laptops, tablets and phones alongside the necessary upgrades for the power budget, matching backbone throughput for 
switches and routers, and another review of the site survey to utilize 5ghz as more of a "best effort" band.

Do be noted that Wi-Fi 7 is the future as more and more demanding technologies will require higher and higher throughput, especially in technological advances for virtual reality 
(VR) and immersive learning environments that use VR.

Listed are some of the current technologies Wi-Fi 7 will bring to the table:

- 6 GHz Band — A new Wi‑Fi band (5925–7125 MHz) offering very wide channels, low interference, and support for Wi‑Fi 6E and Wi‑Fi 7.

- 320 MHz Channels — Extremely wide channels available only in 6 GHz; enable very high throughput and low latency.

- MLO (Multi‑Link Operation) — A Wi‑Fi 7 feature allowing devices to use multiple bands or channels simultaneously for higher throughput, lower latency, and improved reliability.

  - MLO Subtypes:
    - MLMR (Multi‑Link Multi‑Radio) — Each link uses its own dedicated radio; highest performance and lowest latency.
    - EMLSR (Enhanced Multi‑Link Single‑Radio) — A single radio rapidly switches between links; more power‑efficient but slightly higher latency. Most mobile devices will use this.
    - STR / MSTR (Simultaneous Transmit & Receive / Multi‑Link STR) — Allows transmitting on one link while receiving on another; improves responsiveness and reduces contention.
    - NSTR (Non‑Simultaneous Transmit & Receive) — Alternates between transmit and receive across links; simpler and more power‑efficient.

- QAM (Quadrature Amplitude Modulation) — A modulation scheme that encodes data in amplitude and phase changes.
    - 1024‑QAM (Wi‑Fi 6) — Higher density modulation for increased throughput.
    - 4096‑QAM (Wi‑Fi 7) — Even denser modulation enabling significantly higher data rates.

- Preamble Puncturing — Allows an AP to “puncture” (skip) parts of a bonded channel (ex. 120 Mhz channel) that are occupied or interfered with, enabling use of the remaining large bandwidth instead of falling back to a narrower channel.
- Multi‑RU (Resource Unit) Allocation — Wi‑Fi 7 can assign multiple Resource Units (RUs) to a single client, improving efficiency and throughput for management frame overhead.
- OFDMA Enhancements — More flexible scheduling and better parallelism for multi‑client environments.
- Deterministic Latency — Wi‑Fi 7 introduces scheduling improvements for consistent low‑latency performance (important for AR/VR, gaming, and real‑time applications).
- Enhanced Security (WPA3 & WPA3‑E) — Wi‑Fi 7 continues to rely on WPA3 but includes optional enhancements for enterprise environments and multi‑link authentication.
- AFC (Automated Frequency Coordination) — A regulatory system allowing higher‑power 6 GHz operation outdoors or in large venues by coordinating frequencies to avoid interference with incumbent users.

- 6 GHz Client Types:
    - LPI (Low‑Power Indoor) — Indoor‑only devices with moderate power limits.
    - SP (Standard Power) — Higher‑power devices allowed when AFC is used.
    - VLP (Very Low Power) — Ultra‑low‑power devices for wearables and mobile use.

- Reduced Contention — 6 GHz eliminates legacy Wi‑Fi protocols (no 802.11b/g/n clients), reducing overhead and improving efficiency.




# 4. LAYERS 1 - 7 TROUBLESHOOTING

This section touches on common network issues related to Wi-Fi which are almost always in the Layer 1 and Layer 2 of the OSI model.
Two of the biggest (and almost only) factors that affect Wi-Fi connectivity are:
	- Client devices (i.e. end users)
	- Poor wireless infrastructure

Client devices are what your end-users are, and these devices generally span anywhere from 4-5 generations of the 802.11 standards. A lot of troubleshooting will mainly be from depreciated technologies, congested bands such as 2.4 Ghz, and general incompatibility with newer 802.11 standards as the corporate infrastructure updates.

Poor wireless infrastructure is mainly from bad deployments of AP's and depreciated equipment. Older AP's only using 2.4 Ghz, older standards being used such as 802.11n and older, insufficient PoE budget, AP's having too large of a cell coverage area, etc. These are some examples of bad infrastructure deployments.

Note: Layers 3-7 will be sparse and updated as use-cases present themselves. Most issues at these layers are either network-dependent (ex. is the WAN choking the datarate?) or application-specific (are their driver issues with the end-user devices?).
	- Linux users: a lot of Wi-Fi issues present themselves on Linux environments almost exclusively on the application layers; especially on Arch Linux. Verification will need to be done for your specific Linux build before Wi-Fi issues should be considered.


## 4.1 LAYER 1 - PHYSICAL

A lot of the physical layer is ethereal in nature (due to the fact we can't physically see "Wi-Fi") and requires basic theoretical knowledge. Fortunately, most of that can be explained here:
- ***Signal strength,*** or the received strength of the signal from the AP
- ***Signal-to-Noise Ratio,*** or background noise relative to the signal strength
- ***Signal interference,*** or what other client devices, radio interferences or obstructions are doing to disrupt the signal.
- ***Signal attenuation,*** or loss of signal. Every 3dBm of attenuation is 50% reduction of the current signal.
- ***Airtime contention,*** or the amount of devices fighting for the chance to transmit on the Wi-Fi band(s)
  - Remember, Wi-Fi is a half-duplex medium, or only that one radio can either transmit or receive at a time and not both at the same time.

Fortunately, there are also mobile apps that can measure certain metrics such as RSSI levels (signal strength). A couple apps you can use are:

#### Android

[WiFiman by Ubiquiti](https://play.google.com/store/apps/details?id=com.ubnt.usurvey&hl=en_US) - Ubiquiti's Wi-Fi analyzer. works best in a Unifi ecosystem.

[Wifi Analyzer Pro](https://play.google.com/store/search?q=wifi%20analyzer%20pro&c=apps&hl=en_US) - Good dashboard view for all channels, channel congestion and speed tests

[Networker Analyzer Pro](https://play.google.com/store/apps/details?id=net.techet.netanalyzer.an) - Good for a general network overview on a dashboard

#### Apple

[Wifiman by Ubiquiti](https://apps.apple.com/us/app/ubiquiti-wifiman/id1385561119)

[Netspot WiFi Analyzer](https://apps.apple.com/us/app/netspot-wifi-analyzer/id1490247223)

## 4.1.1 What is the signal strength?

From best to worst:
| RSSI Level | Quality | Usability |
|-----------:|---------|-------|
| **-30 dBm** | Excellent | Practically sitting on top of the AP. |
| **-40 dBm** | Excellent | — |
| **-50 dBm** | Excellent | — |
| **-60 dBm** | Excellent | -65 dBm is the minimum required for voice Wi‑Fi. |
| **-70 dBm** | Good | Voice Wi‑Fi becomes unreliable. |
| **-80 dBm** | Fair | Video buffering; email/web browsing only. |
| **-90 dBm** | Poor | Generally unusable due to SNR floor. |
| **-95 dBm** | Unusable | Almost all data transmission is corrupted/lost. |

The easiest fix for poor RSSI levels is to add another AP to cover gaps in coverage or move clients closer to the AP. Boosting power should be a last resort to prevent sticky clients and other AP's interfering with each other.
		
### Is Anything Impeding the Signal?

This can generally be diagnosed into three troubleshooting methods, ordered from most to least common:
- Co-channel interference
- Signal-to-Noise Ratio (SNR)
- Signal interference

## 4.1.2 ***Co-channel interference (CCI)***

One of the biggest factors in interference, are other client taking up airtime on the same channel and raising the SNR floor.
- CCI is clients roaming from the same channels and choking airtime due to limited uses of channels within a band.
		- 2.4 Ghz is the best example of CCI because there are only three non-overlapping USA channels (1-6-11).
		- 5 Ghz and 6 Ghz can have the same issue if the same channels are used for all AP's in a given range.
		- The best solution is to diversify your 5 and 6 Ghz channels and phase out 2.4 Ghz or move over to "best effort"

## 4.1.3 ***Signal-to-noise Ratio (SNR)***

SNR is the dBm background noise/noise floor relative to the received dBm signal of a device. *A low SNR* will both corrupt transmissions and reduce datarate speeds.
- The higher the noise floor, or background noise, the worse the SNR.
   - A bad SNR would be 15 and lower, meaning the background dBm is near equal to the signal dBm.
    - A good SNR would be 25 and higher, meaning there is a very clear boundary from the background dBm and the signal dBm.
    - To calculate the SNR, you take the dBm of the noise floor and subtract it to the received signal in positive form. A few examples would be:

| Noise Floor (dBm) | Signal (dBm) | **SNR** | Interpretation |
|------------------:|-------------:|--------:|----------------|
| -100 | -85 | **15 dB** | Bad ratio. |
| -100 | -75 | **25 dB** | Okay ratio. |
| -100 | -65 | **35 dB** | Great ratio. |
| -85  | -70 | **15 dB** | High noise floor |


- SNR is always poor on the 2.4 Ghz band. The best solution is to move away from 2.4 Ghz to 5/6 Ghz.
- Shrinking the cell sizes of the AP's and moving over to diversified 5ghz/6ghz channels will provide a better SNR.

## 4.1.4 ***Walls (signal interference)***

Depending on material, walls can reduce the dBm signal by a greater or less degree, effectively reducing your signal strength by half or more.
- For every 3dBm attenuated is half of your signal being absorbed or lost. Generally speaking:
  - American drywall/gypsum will reduce your signal by 50%, leaving you with 1/2 the original strength.
  - Large office glass walls will reduce the signal by 75%, leaving you with 1/4 of the original strength.
  - Concrete will reduce your signal by 90-95%, leaving you with ~1/14'th of the original strength.
- For every 10dBm attenuated is your signal becoming *10 times weaker,* or a 90% loss of the originl signal.

*Note: It can be easily referenced that anything which reduces the signal by more than 3 dBm will cause significant Wi-Fi issues.*




This is a table from [UrsaMajor Lab](https://www.ursamajorlab.com/blog/wifi-signal-attenuation-wall-materials-2-4ghz-5ghz-6ghz/) charting the various attenuations that can happen across all three Wi-Fi bands through common materials:

### *SECTION: MATERIAL ATTENUATION TABLE (2.4 GHz / 5 GHz / 6 GHz)*

*Attenuation values represent approximate dB loss when a Wi‑Fi signal passes 
through common building materials. Higher frequencies (5 GHz, 6 GHz) 
experience greater loss.*

| Material                     | 2.4 GHz | 5 GHz  | 6 GHz  |
|-----------------------------|--------:|-------:|-------:|
| **Brick Wall (15–20 cm)**        | 8–12 dB | 12–18 dB | 15–22 dB |
| **Concrete Wall (15 cm)**        | 15–25 dB | 25–35 dB | 30–40 dB |
| **Glass (0.5–1 cm)**             | 1–3 dB  | 3–5 dB   | 5–7 dB   |
| **Gypsum Board (1–2 cm)**        | 2–4 dB  | 4–6 dB   | 6–8 dB   |
| **Metal Wall**                   | 35–45 dB | 40+ dB  | 45+ dB  |
| **Wooden Wall (2–5 cm)**         | 3–6 dB  | 6–10 dB  | 8–12 dB  |

This is a table from [NIST hosted by wifivitae](https://wifivitae.com/2021/12/15/wall-attenuation/) charting various other materials that can attenuate Wi-Fi bands

### *NIST High‑Precision Values (Additional Reference)*

| Material                         | 2.4 GHz | 5 GHz | 6 GHz |
|----------------------------------|--------:|------:|------:|
| **Brick**                        | 6 dB    | 15 dB | 15 dB |
| **Brick‑faced Concrete**         | 18 dB   | 41 dB | 48 dB |
| **Brick‑faced Masonry Block**    | 10 dB   | 32 dB | 43 dB |
| **Concrete (102 mm)**            | 15 dB   | 22 dB | 25 dB |
| **Concrete (203 mm)**            | 29 dB   | 48 dB | 54 dB |
| **Drywall / Panel**              | ~1 dB   | ~1 dB | ~1 dB |
| **Glass (6 mm)**                 | 1 dB    | 1 dB  | 1 dB  |
| **Lumber (Dry)**                 | 3 dB    | 4 dB  | 4 dB  |
| **Masonry Block**                | 11 dB   | 15 dB | 16 dB |
| **Plywood (6 mm)**               | ~1 dB   | ~1 dB | ~1 dB |
| **Reinforced Concrete (203 mm)** | 31 dB   | 55 dB | 63 dB |



## 4.1.5 ***AP Placement (signal interference)***
- Most AP's people buy are omni-directional internal antennas. They have, generally speaking, a 360° azimuth footprint.
  - These need to be mounted on a ceiling pointing face-down no greater than 25ft/7.5m from the ground.
  - Metal beams or other infrastructure can attenuate and lose a signal if an AP is near or attached to such an object.

## 4.1.6 ***Obstructions (signal interference)***
- Objects between an AP and the client's device can reduce or even block a signal. A few examples are:
  - Metal filing cabinets can block a signal
  - Being closest to the other side of a wall the signal is penetrating can be a dead zone as the signal diffracts.
  - Older IoT devices can suffer from signal scattering from metal objects, metal racks and heavy machinery.
    - Warehouses using older scanners such as a Motorola MC9090G can suffer greatly from scattering due to legacy 802.11 standards.
			- Newer tech using the 802.11n standard helps with multipathing and scattering.
- A lot of people in a high-density or very high-density environment can absorb a massive amount of the signals.
	- Places like stadium, gymnasiums and large events absolutely require expert consultation due to the complexity of such deployments and the specific use-cases and scopes of these events.

## 4.1.7 ***Radio Interference (RF) (signal interference)***
- This is radio frequencies affecting the Wi-Fi band itself.
- Microwaves, Bluetooth, cordless computer mice/keyboards, cordless phones, Zigbee devices, USB 3.0 devices and fluorescent lights can all interfere with the 2.4 Ghz band.
- DFS can cause some 5 Ghz channels to become unavailable.

## 4.1.8 ***AP Limitations*** 

How much traffic the AP itself can handle is a key consideration. The three most important things above anything else for good Wifi is:
- Minimal airtime contention (how many clients are trying to talk to the AP in the same time frame).
- What 802.11 standard are the AP's at (which 802.11 standard can they support up to?).
- Bandwidth (how much actual throughput is there?).

## 4.1.9 ***Airtime contention***

Generally speaking, airtime contention is how many clients are fighting to just talk to the AP in order to transmit data.
- This isn't strictly bandwidth but rather management frame overhead.
  - An analogy would be the amount of people in a room talking:
    - Two people talking in one room with only two people is easy to hear.
    - Two people talking in one room with many people can be harder to hear.
    - Multiple people talking in one room with many people can be really hard to hear.
    - The more devices you have, the more airtime contention there will be.
	- This means things like Wi-Fi calling and video streaming can greatly be impeded by the amount of people on an AP
		- AP's can only talk to so many devices at once. This is usually broken down by a vendor datasheet with a MU-MIMO specification list that usually looks like "2x2" (shorthand) or "2x2:2:2" (long-form).
			- Don't forget that radios operate on a half-duplex medium: only one radio can transmit or receive at a time.
			- The 2x2 represents two transmitters (Tx) and two receivers (Rx) that can communicate at once. These numbers can also be 4x4, 8x8 or even up to 16x16.
			- 2x2:2:2:2 is an usually unlisted specification that represents the 2x2 Tx/Rx group and the:
				- 2x2:2 = Spatial stream or how many streams of data can be transmitted at once to a single user
				- 2x2:2:2 = How many spatial streams of data can be transmitted at once to multiple users
				- 2x2:2:2:2 = How many clients can receive a spatial stream at once
			- Essentially what these mean is either one client can receive two separate streams of data (doubling bandwidth or throughput) or two clients can receive one stream of data at once. The more streams, the more clients that can be handled at the same time.
				- More common devices can have numbers that look like 2x2(2.4ghz), 4x4(5ghz), 2x2(6ghz) which is multiple MU_MIMO streams across three different bands, potentially supporting up to 8 clients at once.
					- It should be noted though 2.4ghz should be phased out except for certain IoT devices or used as a "best effort" band for low-priority traffic in enterprise environments. High density environments shouldn't deploy 2.4ghz.

## 4.1.10 ***802.11 standards***

The variability of the generations of 802.11 generations and standards will greatly affect how your Wi-Fi environment will function.
- Wifi quality is heavily dictated by what 802.11 standard both the device and AP is at. If you were to use the ancient 802.11b in today's era for example, it would be as if you were stuck in 2003 relying on datarates barely reaching 1-2mbps. Browsing and email would be virtually impossible, let alone streaming videos or wifi calling.
- Most legacy devices are either using 802.11n or 802.11ac, ratified 17 and 13 years ago as of 2026, respectively. Most enterprises and SOHO/SMB's are currently on these standards.
- 802.11ax is recently being adopted widespread with the adoption of the 6ghz band but older devices may still not support 6ghz even though they are listed as a 802.11ax device.
- 802.11be is the newest standard released 2024 expanding on 802.11ax with 6ghz band technologies, adding mandatory security checks and is generally considered to be "Wi-Fi 7"
  - Note: Vendors advertise "Wi-Fi 7" or different variants of the name but actual support of 802.11be technologies are certified under the Wi-Fi Alliance as "Wi-Fi CERTIFIED 7™"
- If quality is suffering for Wi-Fi clients, it could be as simple as rolling out a new generation of wireless devices for both AP's and clients.

## 4.1.11 ***Wi-Fi Bandwidth*** 

Wi-Fi bandwidth is the throughput Wi-Fi devices can handle.
- Bandwidth is tied in with 802.11 standards due to advances in technology. Generally speaking, your speeds will be reflected by the latest 802.11 standards that both AP and client are using.
  - 802.11b devices from 20 years ago have really slow, realistic speeds of ~2mbps and a theoretical maximum of 12mbps. 802.11be devices from yesterday has theoretical maximum of 46gbps and a realistic speeds of 2-5gbps. Thousands of times faster.
- As with the 802.11 standards, increasing performance could just be as simple as upgrading hardware. A few quick calculations can give a good range of what needs to be supported and how many AP's are needed:
  - First, find out what types of devices and what the average bandwidth consumption will be per band channel.
    - Example 1: A phone with a supported datarate of 65mbps and a realistic datarate use of 30mbps. The phone will stream 15mbps for 4k video
      - Divide the app data by the realistic datarate
        - 15mbps / 30 mbps = 50% airtime on a channel
      - Example 2: A laptop with 2x2:2 MIMO with a supported datarate of 130mbps and a realistic datarate use of 70mbps. The laptop will stream 15mbps for 4k video
        - 15mbps / 70 mbps = 21% airtime on a channel
          (Note: As can be seen for this example, more modern tech is a lot more efficient than older tech, practically quadrupling efficiency as we see in the next step.)
  - Second, calculate the number of devices an AP can support using said datarates. 80% utilization is a rule of thumb of when an AP is burdened.
    - Equation: 80 / single device airtime consumption = Number of devices per AP
    - Example 1 (phone): 80 / 50 = 1.6 devices supported (so only one optimally and maybe two!)
    - Example 2 (laptop): 80 / 21 = 3.8 devices supported (almost quadrupled!)
      - Third, calculate the total number of AP's needed to support your total client count.  Our examples will use 30 users for a small business.
        - Equation: (Number of devices x single device airtime consumption %) / 80% = Number of AP's needed
        - Example 1 (phone) (30 phones x 50%) / 80% = 18.75 AP's or 19 AP's in total
        - Example 2 (laptop) (30 laptops x 21%) / 80% = 7.88 AP's or 9 AP's in total
      - Fourth, reduce the total AP count with AP's that can handle dual-band transmission (should be a default option for 2026). Usually this can halve your count plus one or two to accomodate for the AP burden
        - Example: Unifi E7 has 4x4 for both 5ghz and 6ghz for up to 8 spatial streams that can all handle 4k streaming. Example 1 would only need about 10-11 E7 AP's in total.
        - Example 2 would only need about 5-6 E7 AP's  

## 4.1.12 ***Lesser-known problems and miscellanous issues.***
- What is the switch's PoE power budget? Switches can only allocate their maximum budgeted wattage.
  - As more AP's with 4x4:4 capabilities are introduced, wattage per AP is going to increase past 15.4 watts per AP, going upwards of 30, 45, 60, 75 and 90 watts.
- Firmware bugs?
  - Was there a recent update to the wireless controller or AP? This will be more common with Wi-Fi 7 deployments.



## 4.2 LAYER 2 - MAC LAYER

The biggest issues that happen with layer 2 are retransmissions within the MAC sublayer and a lot of this is going down a checklist and verifying your architecture setup is within specification.
Retransmissions means more airtime contention and less quality. This can manifest in a few different ways:
- Layer 1 interference causing data loss/corruption which causes more retransmission rates
- Other AP's causing interference
- Client stations causing interference
- Improperly configured power levels
- Security verification issues
- Certification issues in 802.1X systems
- Congested airtimes and overloaded utilization rates

## 4.2.1 ***Layer 1 interference*** 

This is layer 1 RF disruptions to the Wi-Fi bands causing layer 2 issues, normally through retransmissions congesting airtime.
- Multipathing issues, RF interference, and a low SNR will cause layer 2 retransmissions.
  - Multipathing for legacy devices (such as old inventory scanners) can suffer retransmission issues.
- A microwave oven is probably the most notorious example of RF interference causing layer 2 retransmissions in the 2.4 Ghz band.
  - It's not an uncommon situation to lose internet connectivity for an hour during lunchtime.
- A low SNR causes data corruption as the received signal is obfuscated by the ambient noise floor.
  - Lower SNR will also cause the AP and the client device to "shift down" to a lower data rate speed known as Modulation and Coding Scheme (MCS)
  - Solution: A spectrum analyzer will pick up interferences and either:
    - The offending devices can be removed
    - You move clients to a different Wi-Fi band.
- Adjacent Channel Interference (ACI)
	  - Distorts the signal due to competing clients and AP's, leading to high data corruption due to a smaller SNR.
	  - Solution: Diversify the current channel setup between AP's.

## 4.2.2 ***Hidden Nodes*** 

Hidden nodes are devices that are hidden from each other, unable to see which device is requesting airtime and causing collisions and increasing retransmission rates.
- This is where an obstruction can be between clients. Clients usually "wait in line" due to the half-duplex nature of Wifi and if clients can't see each other, two or more can transmit at the same time and cause layer 2 collisions.
  - Obstructions can be things like walls, metal racking, filing cabinets and metal desks. Think of a phone being stuck in a drawer and still communicating with the AP.
    - This is why hallway AP placements can be a bad idea since 4-12 or more clients can be trying to communicate to an AP at once and not see each other due to the walls obstructing everyone.
  - Power levels on an AP can be too high, causing excessive reach where the clients can hear the AP on opposite ends but the clients can't hear each other.
  - Solution: Identify the hidden node and:
    - Remove the device if it doesn't need connectivity
    - Add another AP if connectivity is needed
    - Enable CTS/RTS

## 4.2.3 ***Mismatched power*** 

This is incorrect power settings on AP's that can cause all sorts of problems:
  - It is possible the AP's signal can reach further than the client device can send the signal, causing the client to be stuck in a loop where it sees the AP but can't communicate with it.
  - There is also the inverse where the client device is communicating to several AP's at once, causing a CCI issue.
  - Solution: Reduce AP power to shrink cell coverage and add more AP's as needed.

## 4.2.4 ***Security verification issues***
- Pre-shared Key (PSK) is one of the most common security types used for Wi-Fi and usually comes down to:
  - Wrong password typed in (it happens.)
  - Bug in a network device
    - Solution: enable/disable device or power cycle device.
    - Sometimes a dongle is needed as a secondary wifi connection to allow a vendor device to be able to "phone home" again and reupdate its drivers.
		- Unsupported security algorithms. WEP and WPA (not WPA2) is depreciated and considered obsolete and phased out.

## 4.2.5 ***802.1X/EAP (WPA2-Enterprise)***
More complicated than just WPA2-PSK (having a certificate authority instead of just a password) and thus can have multiple points of failure. 802.1X needs to be broken down into two zones for troubleshooting:

- ***Zone 1, network backend communications.*** - AP, RADIUS server and CA server.
  - Zone 1 should always be checked first to verify 802.1X is operating normally in the first place.
    - There are usually four possible points of failure:
      - Shared secret mismatch, mainly caused by mistyped password.
      - Incorrect IP settings on AP or RADIUS server.
      - Authentication port mismatch (defaults are UDP 1812 and UDP 1813). Older RADIUS servers might use ports 1645 and 1646.
      - LDAP communications error, usually from a network error where LDAP and RADIUS can't communicate or from an expired account.
- ***Zone 2, Supplicant Certificate Problems*** - (or client-side)
  - Zone 2 should be checked after verifying the 802.1X setup is operating normally.
    - Does the RADIUS server state whether the SSL/TLS tunnel is created? If not:
    - Is the root CA certificate installed in the incorrect certificate store?
      - Should be installed in a Trusted Root Certificate Authorities store. Default location store is usually a personal store of a Windows machine.
      - Is the incorrect root certificate chose?
      - Did the server certificate expire?
      - Did the root CA certificate expire?
      - Is the supplicant clock settings incorrect?
    - Are the tunneled protocols matching? Ex: PEAPv1 with PEAPv1.
    - Credential failures
    - Expired user account/password.
	    - Wrong password.
      - User account doesn't exist in the LDAP.
      - User account isn't joined to the Windows domain.
      - RADIUS attributes mismatch:
        - VLAN mismatches or role-based accounts could attribute to certificate failures.

## 4.2.6 ***Roaming issues*** 

Roaming is the ability for clients to roam from AP to AP without losing connectivity. The biggest contributor to roaming failures is just a poor wireless design. Common issues are:
- AP's haphazardly place wherever and installed incorrectly/improper AP's used.
  - Omni-directional or saucer AP's should be mounted on ceilings no greater than 25 feet/7.5 meters instead of walls or auditorium ceilings greater than 25 feet/7.5 meters.
  - External antenna AP's should be mounted vertically, pointing down.
  - Not enough AP's.
    - This will produce dead zones or too many clients trying to talk to too few AP's, causing airtime contention.
  - Too much transmit power on the AP's.
    - Causes "sticky clients" where the client devices refuse to roam.
    - If multiple AP's are overlapping heavily, the client device can start switching constantly between AP's and degrade performance through multiple retransmissions
  - No secondary coverage
    - In order to roam seamlessly, AP cells should overlap slightly so devices can see a secondary connection point. General rule of thumb is 15-20% overlap.
      - This overlap is best measured by the RSSI being -65 to -70 dBm between two different AP's.
- Older protocols
  - Older 802.1X protocols can introduce upwards of 700ms of latency transitioning from AP to AP
		- This will absolutely ruin any voice Wifi setup
      - Any legacy devices that don't support 802.11k/r/v standards will suffer the same issues
- Not all client devices are created equally
    - Ultimately client devices decide when to roam
    - Apple devices are the most notorious example of sticky clients not wanting to roam

## 4.2.7 ***Channel utilization*** 

This is the total airtime being used at a given point in time per channel. Oversaturation can happen to channels with too many clients and too many high-bandwidth applications running at the same time with too few AP's. Think of several people trying to stream 4K video at once.
- Rule of thumb with threshold margins for wireless traffic:
    - +80% utilization means all 802.11 traffic will be affected
    - +50% utilization means video traffic will be affected
    - +20% utilization means voice traffic will be affected
      - Solution: Use more AP's with a smaller cell size to reduce channel utilization per AP.
        - Note: Be sure that your uplink bandwidth is great enough to accommodate an uptick of bandwidth usage!
- Common issues that can also saturate channels are:
  - Improper channel planning leading to CCI
  - Too many broadcast SSID (the more connection points an AP has to maintain, the more overhead the AP needs to deal with)
  - Basic data rates less than 25mbps can saturate a channel
  - Too many legacy devices bog down airtime traffic (think of slow drivers causing traffic jams)


## 4.3 Layer 3 - IP

Generally speaking, this is outside of wireless and more relegated to the wired network infrastructure. DHCP can be inspected to verify whether there's an issue with the 
leasing to wireless clients or if there is a wired network problem. 

Most vendors have a diagnostic tool that can verify whether the VLANs are operating normally with DHCP requests. The order of operation is:
  1. Probe across a range of VLANs
  2. Multiple DHCP requests are sent out across designated VLANs up the 802.1Q trunk o the DHCP server
  3. DHCP acknowledges and sends a lease offer
  4. Management AP doesn't need an IP for the probe, so it replies with a negative-acknowledge (NAK) response
    - If:
      - The DHCP lease offer reaches the AP, then the wired portion of the network is fine
      - The DHCP lease offer does not reach the AP, then the wired portion of the network is not okay.







## 4.7 Layer 7 - Application

-Was the driver updated?
-What do the logs show? (Event viewer - Windows. systemctl - Linux)


## Voice wifi: (Work in progress)

-Very finicky, requires less than 5% retransmission rates
-Consistently requires -65dBm or less
-5ghz and 6ghz the best band to prevent CCI
