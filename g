
Case Study: InterOptic Saves the Planet (Part 1 of 2) 
The Case:  In his quest to save the planet, Inter0ptic has started a credit card number recycling program. ‘‘Do you have a database filled with credit card numbers, just sitting there collecting dust? Put that data to good use!’’ he writes on his web site. ‘‘Recycle your company’s used credit card numbers! Send us your database, and we’ll send YOU a check.’’ For good measure, Inter0ptic decides to add some bells and whistles to the site, too ... 
Meanwhile ... MacDaddy Payment Processor has deployed Snort NIDS sensors to detect an array of anomalous events, both inbound and outbound. An alert was logged at 08:01:45 on 5/18/11 concerning an inbound chunk of executable code sent to port 80/tcp for inside host 192.168.1.169 from external host 172.16.16.218. Here is the alert:
[**]  [1:10000648:2]  SHELLCODE  x86  NOOP  [**]
[ Classification: Executable code was detected]  [ Priority:  1]  05/18 -08:01:45.591840 172.16.16.218:80 -> 192.168.1.169:2493 TCP TTL :63 TOS :0 x0 ID :53309 IpLen :20 DgmLen :1127 DF
*** AP ***  Seq: 0 x1B2C3517   Ack : 0 x9F9E0666   Win : 0 x1920    TcpLen :  20
Challenge:   You are the investigator  ... 
•	First, determine whether the alert is true or false:
-	Examine the alert’s data to understand the logistical context.
-	Compare the alert to the rule, in order to  better understand  what it has been  built  to detect.
-	Retrieve the packet that triggered the  alert.
-	Compare the rule to the packet to understand  why it   ﬁred.
•	Subsequently, you’ll want to determine if there are any other activities that are related to the original event.
-	Construct a timeline of alerted activities involving the potentially malicious out- side host.
-	Construct a timeline of alerted activities involving the target.
Network:    The MacDaddy Payment  Processor network  consists of three  segments:
•	Internal network: 192.168.1.0/24
•     DMZ: 10.1.1.0/24
•	The “Internet”: 172.16.0.0/12 [Note that for the purposes of this case study, we are treating the 172.16.0.0/12 subnet as “the Internet.” In real life, this is a reserved nonroutable IP address space.]
Other domains and subnets of interest include:
•	.evl—a top-level domain (TLD) used by Evil  systems.
•	example.com—MacDaddy Payment Processor local domain. [Note that for the pur- poses of this case study, we are treating “example.com” as a legitimate second-level domain. In real life, this is a reserved domain typically used for examples, as per RFC 2606.]
Evidence: Security staﬀ at MacDaddy Payment Processor collects the Snort alerts for the day in question and preserves the “tcpdump.log” ﬁle that corresponds with the alerts. At your request, they also gather the relevant Snort sensor’s conﬁg and rules. You are provided with the following ﬁles containing data to analyze:
•	alert—A text ﬁle containing the Snort sensor’s default “alert” output, including the alert of interest above.
•	tcpdump.log—A libpcap-generated ﬁle that contains full-content packet captures of the packets involved in the events summarized in the above “alert” ﬁle.
•	snort.conf—A text ﬁle containing the conﬁguration description of the Snort sensor, including the rules.
•	rules—A folder containing the Snort rules that were in use by the sensor, as included by the conﬁguration above  (/etc/snort/rules).
The NIDS was conﬁgured to use MST (Mountain Standard Time).  
Analysis – Snort Alert
Using the Snort alert ﬁle provided, let’s examine any instances of the “SHELLCODE x86 NOOP”  alert:  (Open your Module_6_Files in Documents folder and enter your terminal CLI from this folder)
$  grep -A 4  ‘x86 NOOP’ alert
1.	Capture a screenshot of your result.
a.	What is the IP address of the remote server that sent the traffic that caused the alert?
b.	What is the local system IP address that received the packet?
c.	What type of packet appears to be the payload of the IP packet?
d.	What is the port number?
e.	What type application packet does this most likely indicate?
f.	What is the ID of the alert?
This is the alert that security staﬀ initially provided us and, based on the output of “grep,” it appears that there are no other alerts of this type in the packet capture.
Initial Packet Analysis
Let’s pull the corresponding packet out of the associated capture so  that we  can examine it more thoroughly. Using tcpdump and the BPF language we can ﬁlter on the IP ID ﬁeld  using the value shown in the alert.
$ tcpdump -nnvr tcpdump.log ' ip [4:2] =  IP ID# ' 
2.	Capture a screenshot of your result.
a.	Compare the results of this output with your previous output; list the values that compare.
This certainly  appears  to  be  the  packet  that  caused  the  alert.  In  addition  to  the  IP ID number that matches the alert, further corroboration is provided by the sequence and acknowledgment numbers.  
Now let’s examine the packet’s contents (in ASCII to begin with):
$   tcpdump   -nnAr   tcpdump.log   ' ip [4:2]   =   IP ID# '
3.	Capture a screenshot of your ouput.
a.	What type of application layer headers does the packet payload appear to contain?
b.	What is the content length?
c.	What is the content type?
The headers also indicate that the web page was provided through a Squid web proxy, “www-proxy.example.com:3128”. Based on the “MISS” result listed in the X-Cache and X-Cache-Lookup headers, the requested page was not already in the Squid cache when requested.
As shown in the “Etag” header, the ETag of the delivered content was “1238- 27b-4a38236f5d880.” This may come in handy for web proxy cache analysis later.
Snort Rule Analysis
Why  would this packet  trigger the “SHELLCODE x86 NOOP” alert? Let’s ﬁnd the rule    and see.  Let’s use “grep” to extract the rule of interest, based on the Snort ID (SID) 10000648:
$  grep  -r  sid :10000648 rules
4.	Capture a screenshot of your result.
a.	Which rules file is the rule located?
As you can see above, this is a very simple rule that ﬁres on any inbound IP content that contains a string of at least 14 contiguous bytes of 0x90, which is a “NOOP” instruction on the x86 architecture. This is a common feature of a buﬀer overﬂow attack attempt.
Based on the rule that was triggered, we would expect the corresponding packet to contain a series of bytes set to 0x90. Let’s view the packet in both hexadecimal and ASCII to see if we can eyeball the match.
$   tcpdump   -nnXr   tcpdump.log   ' ip [4:2]   =   IP ID# '
5.	Capture a screenshot of the result.
Toward the end of the packet, at byte oﬀset 0x040c (1036), we see 16 consecutive bytes of value 0x90. This would appear to be part of the binary JPEG ﬁle, which begins at oﬀset 0x01ec (492).
Whether that string of 0x90 values is a coincidence (used to describe pixel colors) or whether it is a malicious NOOP sled may be up to a reverse-engineering malware (REM) specialist to determine. There are certainly known instances of attacks on JPEG parsing/rendering engines that leverage buﬀer overﬂow issues.
Carving a Suspicious File from Snort Capture
Let’s carve out the suspicious JPEG so that we can provide it to a REM specialist. Since the JPEG appears to be contained in a single packet, we can easily use Wireshark to export the packet of interest. Open the tcpdump.log in Wireshark from the File menu.  Set the filter to “ip.id == IP ID#”.  You will be in frame 135 and then go to the line 01f0 and starting with ff d8 ff fe . . . . (Notice the JPEG “magic number” (0xFFD8) at the beginning); select the section.  Open the File menu tab and select “Export Selected Packet Bytes”.  Name the file and export.  It will go into your Module_6_Files Folder.
Let’s identify the cryptographic checksums of the ﬁle we just exported.
$ md5sum exported file name
$ sha256sum exported file name
6.	Capture a screenshot of the two commands with the checksums.
Bug Alert
We can also look at the subsequent behaviors of the systems in question, based on the evidence sources we already have. For instance, if we think the source of the JPEG might be a bad actor, then it would make good sense to see if there are any other NIDS alerts associated with the IP address:
$   grep   -A   3   -B   2    'Source IP Address'   alert [**]
7.	Capture a screenshot.
a.	Were there any other NIDS alerts associated with our source IP address?
What about the presumed target? Has it been im- plicated in any other alerts? Let’s grep out all alerts relating to the target IP address, and include the preceding two  lines of each alert so that we  can then just  ﬁlter down to the message/SID line. Then we can get a count of unique instances, and sort the alert messages from most common to least:
$   grep   -B   2    'Destination IP Address '   alert   |   grep    '\[\*\*\] '   |   sort   -nr   |   uniq   -c
8.	Capture a screenshot.
a.	What is the most common alert relating to our destination IP address?
b.	How many alerts did the most common cause?
This alert is triggered by an external web server sending an invisible GIF ﬁle to an internal client—a common behavior of web servers trying to track a user as they navigate the web site. (A “web bug” is an object, such as a tiny image ﬁle, which is included in a web page or email in order to track user behavior.) Let’s see what else we can learn about these events.  First, we use “grep” to extract all instances of the  alert (SID 2925, revision 3), and then we ﬁlter down to just our host of interest. This way we can see when the alerts start and stop:
$   grep   -A   5   1:2925:3   alert   |   grep    ‘Destination IP Address '   |   wc   -l 108
$   grep   -A   5   1:2925:3   alert   |   grep    ‘Destination IP Address '   |   head   -1 05/18 -07:45:09.351488 207.46.140.21:80 -> 192.168.1.169:2127 
$   grep   -A   5   1:2925:3   alert   |   grep    ‘Destination IP Address '   |   tail   -1
9.	Capture a screenshot of the results.
a.	What was the timeframe for the receipt of these packets?
It might be interesting to get an aggregate count of the various sources of these web bugs:
$   grep   -A   5   1:2925:3   alert   |   grep    ‘Destination IP Address '   |   awk   '{ print   $2}'   | sort  | uniq  -c  | sort -nr
10.	Capture a screenshot of the result.
Let’s see how many servers were involved.
$   grep   -A   5   1:2925:3   alert   |   grep    ‘Destination IP Address '   |   awk   '{ print   $2}'   | sort  -u  | wc -l
11.	Capture a screenshot of the results.
a.	How many servers were involved?
It appears that the x alerts resulted from traﬃc from y distinct web servers. Looking  up the associated domains and IP address owners, we ﬁnd that these web servers were owned by companies including AOL, Google, Monster, and others.
TCP Window Scale Alert
Now, let’s turn our attention to the next most common alert relating to destination IP address: “TCP Window Scale Option found with length > 14.” This is an alert produced by the Snort preprocessor that parses TCP options and watches for anomalous values. In the command below, we extract all instances of the alert by searching for its “GID:SID:Rev,” and then ﬁlter only for matches that related to our destination IP:
$   grep   -A   6   116:59:1   alert   |   grep   -A   4   -B   2    ‘Destination IP Address '
12.	Capture a screenshot.
Let’s investigate these results.  Looking just at the ﬁrst few results above, we can see a number of things that are suspicious about the traﬃc that caused them, in addition to the size of the window scale option:

•	While the destination host varies, certain other values do not, including the source port and the setting of the Urg, Push, and Fin ﬂags.
•	All of the packets have identical sequence and acknowledgment  numbers!
•	Although the sources and destinations are all on the same network, the time to live (TTL) values are completely inconsistent.

These are clearly crafted packets. Judging from the nonsensical values and ﬂags, they were likely generated by some sort of reconnaissance tool, probably for the purposes of operating system ﬁngerprinting. Often, ﬁngerprinting tools send strange packets to their targets because diﬀerent operating systems and applications respond in diﬀerent ways to unexpected input. By sending strange packets and evaluating the target’s response, ﬁngerprinting tools can compare the target’s response to known values and determine likely software versions.
Let’s look more closely at the timing and sockets of the packets that caused these alerts:
$   grep   -A   5   116:59:1   alert   |   grep    ‘Destination IP Address '
13.	Capture a screenshot of the results.
a.	When do the packets begin?
b.	How long is the attack?
c.	How many hosts are targeted?
d.	What are their IP addresses?
It’s likely that our Destination IP address sent crafted packets to these four hosts for the purposes of reconnaissance.
Timeline
Based on what we’ve discovered so far, we can begin to interpret our NIDS alerts to construct a time-based narrative. Here’s what transpired on 5/18/11 that seems to be of interest to us (times are in MST):

•	07:45:09  NIDS alerts for the destination IP address begin. Though these initial alerts—for web  bug downloads—do not themselves indicate any particularly adverse behavior, they do serve to establish a known commencement of web browsing activity.
•	08:01:45 There is a NIDS alert for possible shellcode being downloaded by the destination IP address from an unknown external web server. This is the NIDS alert that was the impetus of our investigation.
•	08:04:28-08:04:38 Multiple NIDS alerts report crafted packets sent from the destination IP address to multiple internal hosts.
•	08:15:08 NIDS alerts for destination IP address end. The end of the web bug download alerts does not deﬁnitively indicate that destination IP address has ceased to be active on the network, but it does at least indicate a possible change in the operator’s web browsing activities.
14.	Based on the information gathered, what is your theory of the case?
To Be Continued!

Don’t forget to use the template and fill in all the sections.

