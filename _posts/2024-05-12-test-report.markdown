Today, the U.S. Department of Justice announced the arrest of Chinese national Yunhe Wang for his alleged control of a botnet of infected computers associated with the residential proxy service known as "911 S5," following an investigation by the Defense Department's Defense Criminal Investigative Service (DCIS), Federal Bureau of Investigation (FBI), and Department of Commerce's Office of Export Enforcement (OEE). Additionally, the U.S. Treasury Department's Office of Foreign Asset Control (OFAC) sanctioned multiple individuals and entities for their activities associated with the malicious botnet service, including Wang, whose designation included 49 cryptocurrency addresses as identifiers.

Together, addresses associated with Wang hold over $130 million in cryptocurrency on-chain. We'll share more information below, including how law enforcement utilized advanced and novel tactics in blockchain analysis during this investigation.

### What was 911 S5?
911 S5 was a service that provided residential proxy services, often to bad actors who frequently paid for these services in cryptocurrencies such as Bitcoin. The 911 S5 botnet was able to provide these services by distributing deceptive free VPN services to victims, which purported to give users enhanced privacy while browsing the web. In reality, 911 S5 used backdoors in its code to illegally hijack the IP addresses of millions of victims around the world. This enabled the 911 S5 administrators to make millions of dollars per year with a subscription-based service allowing cybercriminals to use victims' IP addresses to carry out password spraying attacks, financial fraud, identity theft, child exploitation, and other forms of cybercrime.

In July 2022, 911 S5 voluntarily shut down their operations, but continued to hold substantial funds on-chain. We're proud to share that tools assisted in the 911 S5 investigation, helping agents discover many of the wallets holding those funds, as well as several others that made up 911 S5’s on-chain infrastructure. Below, we'll dive into some of the blockchain analysis that went into the investigation.

### Beyond following the money: How investigators mapped out 911 S5’s on-chain infrastructure
DCIS agents using solutions established an initial set of addresses belonging to 911 S5 by observing addresses promoted by the service for customer payments and following funds from those addresses to others, including deposit addresses at centralized services. Using Investigations Solutions, agents were able to apply advanced techniques to expand upon the initial set of 911 S5 addresses, ultimately revealing larger networks of participants in illicit activity.

Those investigation tactics revealed the network of 911 S5 wallets we see on the Investigations graph below, which includes personal wallets used to receive payments from cybercriminal customers, exchange deposit addresses, and cold storage wallets utilized by 911 S5 administrators.

Cold storage wallets likely controlled by the 911 S5 team, such as that seen in the upper right-hand corner of the graph above, held 4,322.25 BTC, worth roughly $169 million at the time of reception. Those cold storage wallets show exposure to various mixers, as well as a bulletproof hosting provider based in Russia that has previously been associated with ransomware strains like Dharma and Phobos. As we see above, that cold storage wallet also sent funds to wallets controlled by Wang and named by OFAC as identifiers on Wang's SDN list entry. Wang sent some of those funds to a mainstream exchange, presumably to be converted to cash, with the remaining $136.4 million in Bitcoin still sitting in Wang's OFAC-flagged wallets.

Agents did more than just trace funds through that initial set of 911 S5 wallets. They also employed advanced, data-driven investigative tactics to find an entirely new set of 911 S5 addresses that at first glance were not clearly connected to the initial address set. These tactics stemmed from an understanding of 911 S5’s on-chain business operations — more specifically, the prices it charged for different tiers of spoofing service, which are visible on the screenshot of the service's website below.

Using blockchain transaction data, investigators queried all of the blockchains on which 911 S5 operated to identify all transactions matching the specific prices 911 S5 charged for different service offerings. Investigators then analyzed the addresses with the most "hits" for transactions at those price levels, and lo and behold, found a highly active TRON address that also displayed connections to an exchange deposit address previously identified as belonging to 911 S5. The new address was connected to four other exchange deposit addresses as well, allowing investigators to build out a new network of 911 S5 wallets that wouldn't previously have been identifiable through standard blockchain analysis techniques. We can see that network on the Reactor graph below.

This discovery underlines the importance of working with best-in-class blockchain analysis providers that allow investigators to query on-chain data at scale and conduct criteria-based transaction searches, rather than simply follow funds from one wallet to another.

### We will continue to watch 911 S5’s on-chain funds
While our analysis suggests that 911 S5’s administrator, Yunhe Wang, still controls over $136.4 million in Bitcoin, OFAC's highlighting of the addresses holding those funds means that law enforcement, crypto compliance professionals, and other blockchain observers will know the minute the money moves to a new address.

This investigation represents not just an important blow in the fight against online cyber crime and fraud, but also showcases a valuable new method of blockchain analysis that we hope to see more investigators employ.

### The 2024 Crypto Crime Report
Available now
Get your copy

### Not Investment or Other Advice
This material is for informational purposes only and is not intended to provide legal, tax, financial, investment, regulatory or other professional advice, nor is it to be relied upon as a professional opinion. Recipients should consult their own advisors before making these types of decisions. does not guarantee or warrant the accuracy, completeness, timeliness, suitability or validity of the information herein, and assumes no obligation to update any forward-looking statements to reflect any circumstances that may arise after the date such statements are made. has no responsibility or liability for any decision made or any other acts or omissions in connection with Recipient's use of this material.

911 S5 Botnet Cybercrime Fraud
