# Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166

<p>In this article, we will create a tool that will generate Bitcoin Addresses (P2PKH) using the CVE-2008-0166 vulnerability.&nbsp;This is a research project to find BTC coins on earlier versions of the Bitcoin Core software client.</p>

<p><em>Random number generator</em>&nbsp;that generates&nbsp;<em>&nbsp;</em>predictable numbers&nbsp;&nbsp;<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0166" target="_blank" rel="noreferrer noopener"><strong>CVE-2008-0166</strong></a></p>
<p><a href="https://knowledge.broadcom.com/external/article/97348/vaim-openssl-098100-detected.html" target="_blank" rel="noreferrer noopener">VAIM-OpenSSL 0.9.8/1.0.0 Detected</a></p>
<p>The critical vulnerability version&nbsp;&nbsp;<code>OpenSSL 0.9.8</code>&nbsp;<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0166" target="_blank" rel="noreferrer noopener"><strong>CVE-2008-0166 was</strong></a>&nbsp;&nbsp;populated with process ID only.&nbsp;Due to differences between endianness and sizeof(long), the output is architecture dependent:&nbsp;&nbsp;<em>32</em>&nbsp;-bit big endian (for example,&nbsp;&nbsp;<code>i386</code>),&nbsp;&nbsp;<em>64</em>&nbsp;-bit big endian (for example,&nbsp;&nbsp;<code>amd64, ia64</code>),&nbsp;&nbsp;<em>32</em>&nbsp;-bit big endian (for example, powerpc , sparc).&nbsp;<code>PID 0</code>&nbsp;is the core, and&nbsp;&nbsp;<code>PID_MAX</code>&nbsp;(&nbsp;<em>32768</em>&nbsp;) is not reached by porting, so there were&nbsp;&nbsp;<em>32767</em>&nbsp;&nbsp;possible random number streams for each architecture.</p>
<figure class="wp-block-image"><img src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/6361d36aae42327f846fe907ae18b8e5.png" alt="Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166"></figure>
<p>The Bitcoin Core software client uses the&nbsp;&nbsp;<code>OpenSSL</code>.&nbsp;Specifically, it uses a function&nbsp;&nbsp;<code>«EC_KEY_generate_key()»</code>&nbsp;to generate Bitcoin Addresses&nbsp;&nbsp;<em>(like a key)</em>&nbsp;&nbsp;to receive payments.&nbsp;Old versions of Bitcoin Core generate and store&nbsp;&nbsp;<em>100</em>&nbsp;&nbsp;keys in&nbsp;<code>wallet.dat</code></p>
<p>A new key is generated only when a Bitcoin payment is received.&nbsp;Thus, the Bitcoin Core software client maintains a pool of&nbsp;&nbsp;<em>100</em>&nbsp;&nbsp;unused Bitcoin Keys&nbsp;&nbsp;<em>(addresses)</em>&nbsp;.&nbsp;The state of the internal random number generator depends on what other calls were made to the library&nbsp;&nbsp;<code>OpenSSL</code>&nbsp;<em>prior to the call</em>&nbsp;<code>'EC_KEY_generate_key()'</code>&nbsp;.&nbsp;Challenges affecting the internal state of the RNG:&nbsp;<code>«RAND_add(8)», «RAND_bytes(8)» и «RAND_bytes(32)».</code></p>
<p>So the research was to go through a lot of old bitcoin sources to find out what calls were made that affected the internal state of the RNG before the call&nbsp;&nbsp;<code>«EC_KEY_generate_key()».</code>&nbsp;The call path changes between versions of the Bitcoin Core software client</p>
<p><strong>The study focused on the following versions:</strong></p>
<figure class="wp-block-image"><img title="|  Release date |  Version |" src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/c3b97f9cbae39e158b962e34fff506f9.png" alt="|  Release date |  Version |"><figcaption>|&nbsp;Release date |&nbsp;Version |</figcaption></figure>
<p>Our goal is to generate private keys for each version of the Bitcoin Core software client, for each architecture&nbsp;&nbsp;<code>(le32/le64)</code>, for each process ID and for Bitcoin Addresses&nbsp;&nbsp;<code>(P2PKH)</code>, using a random number from a critical vulnerability.&nbsp;<code>OpenSSL 0.9.8.</code></p>
<p>Ultimately, we will create a Bitcoin Address Generator&nbsp;&nbsp;<code>(P2PKH)</code>&nbsp;and everything will be saved to a file&nbsp;<code>result.txt</code></p>
<figure class="wp-block-image"><img title="Everything will be stored in the Google Drive file storage" src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/f211de35d83b0da836ed37ee7bba25ef.png" alt="Everything will be stored in the Google Drive file storage"><figcaption>Everything will be stored in the Google Drive file storage</figcaption></figure>
<h2>Making OpenSSL Vulnerable Again</h2>
<p>For this we will use the&nbsp;&nbsp;<em>distribution kit&nbsp;</em>&nbsp;<a href="https://github.com/demining/TerminalGoogleColab" target="_blank" rel="noreferrer noopener">«Ubuntu 18.04.5 LTS» from Google Colab</a></p>
<figure class="wp-block-image"><img src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/863ca2632e97c6137636ef19d9871c34.png" alt="Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166"></figure>
<p>Earlier we recorded&nbsp; a&nbsp;<em>video instruction</em>&nbsp;:&nbsp;&nbsp;<a href="https://cryptodeep.ru/terminal-google-colab/" target="_blank" rel="noreferrer noopener">«TERMINAL in Google Colab create all the conveniences for working in GITHUB»</a></p>
<p>Open Google Colab in&nbsp;&nbsp;<a href="https://github.com/demining/TerminalGoogleColab" target="_blank" rel="noreferrer noopener"><strong>Terminal [TerminalGoogleColab]</strong></a></p>
<p>Let’s run the command:</p>
<pre class="wp-block-code"><code>cat /etc/lsb-release</code></pre>
<figure class="wp-block-image"><img title="&quot;Ubuntu 18.04.5 LTS&quot;" src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/1f06455a8cbfab1903bad7533db1aada.png" alt="&quot;Ubuntu 18.04.5 LTS&quot;"><figcaption>«Ubuntu 18.04.5LTS»</figcaption></figure>
<p>Let’s go to&nbsp; the&nbsp;<a href="https://github.com/demining/CryptoDeepTools/tree/main/05VulnerableOpenSSL" target="_blank" rel="noreferrer noopener">«CryptoDeepTools»&nbsp;</a><em>repository</em>&nbsp;&nbsp;&nbsp;and take a look at the details</p>
<pre class="wp-block-code"><code>git clone https://github.com/demining/CryptoDeepTools.git

cd CryptoDeepTools/05VulnerableOpenSSL/

ls -lh</code></pre>
<figure class="wp-block-image"><img src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/33e42d134f9f1fe2bec6a4369ded1b07.png" alt="Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166"></figure>
<p><em>Update and install&nbsp;</em>&nbsp;<strong>g++ libgmp3-dev libmpfr-dev</strong></p>
<pre class="wp-block-code"><code>apt-get update

sudo apt-get install g++ -y
</code></pre>
<figure class="wp-block-image"><img title="install g++" src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/c3358cb58dc2a6835cd9e049d348e4e4.png" alt="install g++"><figcaption>install g++</figcaption></figure>
<pre class="wp-block-code"><code>sudo apt-get install libgmp3-dev libmpfr-dev -y</code></pre>
<figure class="wp-block-image"><img src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/abbee73cd3fc0f32bb825d131f6c1990.png" alt="Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166"></figure>
<figure class="wp-block-image"><img title="install packages libgmp3-dev libmpfr-dev" src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/8ef1b3fbe963ddb353aa063ebd5e788a.png" alt="install packages libgmp3-dev libmpfr-dev"><figcaption>install packages libgmp3-dev libmpfr-dev</figcaption></figure>
<p>In order to&nbsp;&nbsp;<code>OpenSSL</code>&nbsp;make vulnerable again as in&nbsp;&nbsp;<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0166" target="_blank" rel="noreferrer noopener">CVE-2008-0166</a><br>
<em>Download&nbsp;</em>&nbsp;<a href="https://ftp.openssl.org/source/old/0.9.x/openssl-0.9.8c.tar.gz" target="_blank" rel="noreferrer noopener">openssl-0.9.8c.tar.gz&nbsp;</a>&nbsp;<em>and patch system files</em></p>
<pre class="wp-block-code"><code>wget https://ftp.openssl.org/source/old/0.9.x/openssl-0.9.8c.tar.gz
</code></pre>
<figure class="wp-block-image"><img src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/efc1281b40a87e9301437cd44d3a06bf.png" alt="Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166"></figure>
<figure class="wp-block-image"><img src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/c677a7a43cdaf592fa288c1d0717cf0c.png" alt="Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166"></figure>
<pre class="wp-block-code"><code>tar xfz openssl-0.9.8c.tar.gz</code></pre>
<figure class="wp-block-image"><img src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/3b70140f25ff755ed55aca49c7b8b65c.png" alt="Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166"></figure>
<pre class="wp-block-code"><code>mv openssl-0.9.8c openssl-0.9.8c-vuln

cd openssl-0.9.8c-vuln</code></pre>
<figure class="wp-block-image"><img src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/3d18e98de9a34f05cf61c8766c1f817c.png" alt="Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166"></figure>
<pre class="wp-block-code"><code>ls -lh</code></pre>
<figure class="wp-block-image"><img src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/7eb8d384683944cdde59fbcadc9d624e.png" alt="Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166"></figure>
<pre class="wp-block-code"><code>patch -p1 &lt;../make-OpenSSL-0-9-8c-vulnerable-again.diff</code></pre>
<figure class="wp-block-image"><img src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/a25d2f9574d2ed2533fcf6495e780466.png" alt="Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166"></figure>
<h2>In the LE-64 system we use:</h2>
<pre class="wp-block-code"><code>./Configure linux-x86_64 shared no-ssl2 no-ssl3 no-comp no-asm</code></pre>
<figure class="wp-block-image"><img src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/151bd04f2078f6668fa9001ec0281243.png" alt="Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166"></figure>
<pre class="wp-block-code"><code>make depend all</code></pre>
<figure class="wp-block-image"><img src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/dadad05a20fb35f2022d3cd063a53db4.png" alt="Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166"></figure>
<h2>Let’s go back to the content/ directory</h2>
<pre class="wp-block-code"><code>cd /

ls</code></pre>
<figure class="wp-block-image"><img src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/07dac71fc87331f2d7764dcaab3880b1.png" alt="Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166"></figure>
<pre class="wp-block-code"><code>cd content/CryptoDeepTools/05VulnerableOpenSSL/

ls -lh
</code></pre>
<figure class="wp-block-image"><img src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/a80061cffc581eb46cb2f1b9a11dd259.png" alt="Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166"></figure>
<h2>Compilation:</h2>
<pre class="wp-block-code"><code>gcc -o cryptodeepbtcgen cryptodeepbtc.c -I./openssl-0.9.8c-vuln/include -L./openssl-0.9.8c-vuln -lssl -lcrypto

ls -lh
</code></pre>
<figure class="wp-block-image"><img title="cryptodeepbtcgen successfully created!" src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/c70338b5ee1f6991711f03d09c4e2932.png" alt="cryptodeepbtcgen successfully created!"><figcaption>cryptodeepbtcgen successfully created!</figcaption></figure>
<pre class="wp-block-code"><code>LD_LIBRARY_PATH=./openssl-0.9.8c-vuln/ ./cryptodeepbtcgen -h</code></pre>
<figure class="wp-block-image"><img src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/b601a69413aacc3e9efa10ef0fb084fb.png" alt="Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166"></figure>
<h2>All supported versions of the Bitcoin Core software client:</h2>
<pre class="wp-block-code"><code>LD_LIBRARY_PATH=./openssl-0.9.8c-vuln/ ./cryptodeepbtcgen -l</code></pre>
<figure class="wp-block-image"><img src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/77ab0df5baf110bd11c89ccebba0791d.png" alt="Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166"></figure>
<pre class="wp-block-code"><code>crypto &gt; LD_LIBRARY_PATH=./openssl-0.9.8c-vuln/ ./cryptodeepbtcgen -l
#0   - 0.3.24
#1   - 0.8.6-d
#2   - 0.8.6-qt
#3   - 0.9.1-d
#4   - 0.9.4-d
#5   - unknownA
#6   - unknownB
#7   - unknownC
#8   - unknownD
#9   - unknownE
#10  - unknownF
#11  - unknownG
#12  - unknownH
#13  - unknownI
#14  - unknownJ
#15  - unknownK
#16  - unknownA0
#17  - unknownA1
#18  - unknownA2
#19  - unknownA3
#20  - unknownA4
#21  - unknownB0
#22  - unknownB1
#23  - unknownB2
#24  - unknownB3
#25  - unknownC0
#26  - unknownC1
#27  - unknownC2
#28  - unknownD0
#29  - unknownD1
#30  - unknownD2
#31  - unknownD3
#32  - unknownD4
#33  - unknownD5
#34  - unknownE0
#35  - unknownA0x
#36  - unknownA1x
#37  - unknownA2x
#38  - unknownA3x
#39  - unknownA4x
#40  - unknownB0x
#41  - unknownB1x
#42  - unknownB2x
#43  - unknownB3x
#44  - unknownC0x
#45  - unknownC1x
#46  - unknownC2x
#47  - unknownD0x
#48  - unknownD1x
#49  - unknownD2x
#50  - unknownD3x
#51  - unknownD4x
#52  - unknownD5x
#53  - unknownE0x
crypto &gt;
</code></pre>
<h2>Run cryptodeepbtcgen -n 32 -v 0:</h2>
<pre class="wp-block-code"><code>LD_LIBRARY_PATH=./openssl-0.9.8c-vuln/ ./cryptodeepbtcgen -n 32 -v 0 &gt;&gt; result.txt
</code></pre>
<figure class="wp-block-image"><img title="Run cryptodeepbtcgen" src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/f0b894bd8b5866ffcbb33be8842347f2.png" alt="Run cryptodeepbtcgen"><figcaption>Run cryptodeepbtcgen</figcaption></figure>
<p>Everything will be saved in the file storage&nbsp;&nbsp;<code>Google Drive</code>&nbsp;as a text file&nbsp;<code>result.txt</code></p>
<figure class="wp-block-image"><img src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/abb8f18ea7575d6b967bbe083d984943.png" alt="Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166"></figure>
<h2>Checking the private key!</h2>
<figure class="wp-block-image"><img title="Checking the private key on the bitaddress website" src="./Search for BTC coins on earlier versions of Bitcoin Core with critical vulnerability OpenSSL 0.9.8 CVE-2008-0166 - «CRYPTO DEEP TECH»_files/a566c1cd990cad3f07f356f0fd62e7d5.png" alt="Checking the private key on the bitaddress website"><figcaption>Checking the private key on the bitaddress website</figcaption></figure>
<p>Next, it remains to check all generated Bitcoin Addresses for the presence of BTC coins, for this we can use&nbsp;&nbsp;<em>the Python script</em>&nbsp;:&nbsp;&nbsp;<a href="https://github.com/demining/CryptoDeepTools/blob/main/03CheckBitcoinAddressBalance/bitcoin-checker.py" target="_blank" rel="noreferrer noopener">bitcoin-checker.py</a></p>
<p><a href="https://github.com/demining/CryptoDeepTools/tree/main/05VulnerableOpenSSL" target="_blank" rel="noreferrer noopener"><strong>Source</strong></a></p>
<p><strong>Video:&nbsp;<a href="https://youtu.be/zHkXups2I8k" target="_blank" rel="noreferrer noopener">https://youtu.be/zHkXups2I8k</a></strong></p>
<p><strong>Source: <a href="https://cryptodeeptech.ru/vulnerable-openssl">https://cryptodeeptech.ru/vulnerable-openssl</a></strong></p>


----

|  | Donation Address |
| --- | --- |
| ♥ __BTC__ | 1Lw2gTnMpxRUNBU85Hg4ruTwnpUPKdf3nV |
| ♥ __ETH__ | 0xaBd66CF90898517573f19184b3297d651f7b90bf |

