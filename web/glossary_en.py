"""English text of the glossary page (web/glossary.py). The ids are the same in every language, so a link to
/lugat/#dmarc and /en/glossary/#dmarc lands on the same term; tests/test_glossary.py keeps the three in step."""
# ruff: noqa: ISC004  (long paragraphs are written as adjacent string pieces on purpose)

from __future__ import annotations

TITLE = "Websites explained in plain words"
DESC = ("What is a website and why do you need one? HTTPS, DNS, SPF, DMARC, SSL, XSS, SQL injection and other terms "
        "explained in plain words. Use the search box to jump to the word you need.")
LEAD = "How does your website work, and how is it protected? In plain words."
SEARCH_LABEL = "Search by word (for example: DMARC, HTTPS, SQL)"
SEARCH_PLACEHOLDER = "Search…"
RESULTS_LABEL = "Results"
FOUND = "Results: {n}. Press one to jump to that place in the text."
NOT_FOUND = "Nothing found. Try another word (for example: DMARC)."
JUMPED = "Moved to “{title}”."
CONTACT_LABEL = "Questions or suggestions:"
BUTTON = "Check a website"

INTRO = """
<section class="term" id="sayt-nedir" data-k="website web site internet advertising sales trust shop window">
<h2>What is a website, and why do you need one?</h2>
<p>A website is your address on the internet. When people hear about you, the first thing they do is pick up the phone and search. If they find nothing, they often go to someone else.</p>
<ul>
<li><b>For advertising.</b> A website works 24 hours a day. You do not explain prices, your address and your work again each time; you send a link.</li>
<li><b>To sell more.</b> Someone who types “order ... in Baku” into Google can find you, and can order straight away through a button, a form or a WhatsApp link.</li>
<li><b>To make work easier.</b> You no longer answer the same questions over and over. Sign-up, orders and payment can run on their own.</li>
<li><b>For trust.</b> People treat a company with a website differently: it looks serious. A company with no website, or with one the browser marks “not secure”, gives the opposite impression.</li>
<li><b>To show your work.</b> Photos, reviews and examples are in one place, so a customer decides more easily.</li>
</ul>
<p>But building a website is not enough. It has to be secure, fast and readable on a phone, and nobody else should be able to send e-mail in your name. Otherwise customers do not come, Google ranks the site lower and, in the worst case, the site gets hacked. This is what SaytYoxla checks in 30 seconds.</p>
</section>
<p>Below, every term about websites and their security is explained in plain words. Use the search box above to find the one you need.</p>
"""

SECTIONS: list[tuple[str, list[tuple[str, str, str, str]]]] = [
    ("1. The basics", [
        ("internet-sayt-brauzer", "What are a website, a browser and a server?", "web site browser server hosting",
         "<p>A <b>website</b> is a set of files kept on a server (text, images, code). A <b>server</b> is a computer that is always on and connected to the internet. "
         "A <b>browser</b> (Chrome, Safari, Firefox) fetches those files from the server when you type an address and shows them to you as a page.</p>"),
        ("domen", "What is a domain?", "domain name ayfar.dev address .az .com",
         "<p>A domain is the site's name, for example <i>saytyoxla.vercel.app</i> or <i>ayfar.dev</i>. It is convenient for people: nobody has to memorise an IP address written in numbers. "
         "You rent a domain by paying once a year. If you do not renew it in time, someone else can take it.</p>"),
        ("hosting", "What is hosting?", "hosting server space rent vercel",
         "<p>Hosting is the space you rent on a server that keeps your site's files and runs 24 hours a day. If the domain is the address, hosting is the house itself. "
         "The speed and protection of the hosting company directly affect the speed and security of your site.</p>"),
        ("ip-unvan", "What is an IP address?", "ip address",
         "<p>An IP address is the address, written in numbers, of every device and server on the internet (for example <i>216.198.79.1</i>). A domain name is turned into that address.</p>"),
        ("dns", "What is DNS?", "domain name system a record cname txt mx nameserver",
         "<p>DNS is the internet's phone book. When <i>site.az</i> is typed, the browser asks DNS: “which server is this name on?” DNS answers, and the browser goes to that server. "
         "DNS holds other records too: <b>A</b> (which IP the domain points to), <b>CNAME</b> (another name for the same place), <b>MX</b> (which server receives e-mail), <b>TXT</b> (a text record; SPF, DMARC and ownership proofs are written here).</p>"
         "<p>You change these records in the panel of the company you bought the domain from (Namecheap, GoDaddy and so on). A change shows up sometimes after a few minutes, sometimes after a few hours.</p>"),
        ("http", "What is HTTP?", "hypertext transfer protocol",
         "<p>HTTP is the set of rules a browser and a server use to talk to each other. The problem: HTTP is not encrypted. Someone on the same Wi-Fi network (a café, a hotel) can read or change a password or the contents of a form.</p>"),
        ("https", "What is HTTPS?", "http secure encryption padlock lock ssl tls",
         "<p>HTTPS is the encrypted version of HTTP. It is the padlock next to the address. Everything between the browser and the server is encrypted, so nobody outside can read or change it. "
         "HTTPS also proves that the site really is that site. A browser shows a site without HTTPS with a “not secure” warning, and Google ranks it lower.</p>"
         "<p>In SaytYoxla, HTTPS is the heaviest check (20 points). If HTTPS does not work, the total score cannot rise above 39.</p>"),
        ("ssl-tls", "What are SSL and TLS?", "ssl tls certificate encryption protocol tls 1.2 1.3",
         "<p>TLS is the technology that encrypts HTTPS. SSL is its old name, but people still say “SSL certificate”. "
         "Old versions (SSL, TLS 1.0, TLS 1.1) are weak and should no longer be used. Today TLS 1.2 and TLS 1.3 are considered normal.</p>"),
        ("ssl-sertifikat", "What is an SSL certificate?", "certificate letsencrypt expiry date valid",
         "<p>A certificate is the site's identity card. A trusted organisation (for example Let's Encrypt) issues it and confirms that the site really belongs to that domain. "
         "A certificate has an expiry date. When it expires, the browser shows the visitor a large red warning and most people leave.</p>"
         "<p>Many hosting providers issue the certificate for free and renew it themselves. It is still worth checking. SaytYoxla shows how many days the certificate has left; if the certificate is not valid, the score cannot rise above 59.</p>"),
        ("http-https-yonlendirme", "What is the HTTP to HTTPS redirect?", "redirect 301 http https",
         "<p>When someone types the address with <i>http://</i>, the site should move them to the <i>https://</i> version automatically. Without this, some visitors stay on the unencrypted version. SaytYoxla gives this check 8 points.</p>"),
    ]),
    ("2. Security headers", [
        ("basliqlar", "What are HTTP headers?", "header response headers",
         "<p>When a server sends a page, it sends short invisible instructions along with it. These are called headers. Some of them tell the browser: “do not put this page in a frame”, “open it over HTTPS only”. "
         "A developer can add these headers very easily, but many sites forget them. Each one below is a header SaytYoxla checks.</p>"),
        ("hsts", "What is HSTS?", "strict transport security header hsts max-age",
         "<p>HSTS tells the browser: “from now on, talk to this site over HTTPS only”. The browser remembers this and sends no unencrypted request even if someone types <i>http://</i>. "
         "So if someone on the network tries to push the connection down to HTTP (a downgrade), it fails. Done right, <i>max-age</i> is at least 6 months. 6 points in SaytYoxla.</p>"),
        ("csp", "What is CSP (Content-Security-Policy)?", "content security policy header csp xss script",
         "<p>CSP is a list the site gives the browser: “load scripts, images and fonts only from these addresses”. Even if an attacker manages to place a harmful script inside the site, the browser does not run it, because it is not on the list. "
         "That makes CSP the strongest layer against XSS attacks. It is also the header most often left out: in SaytYoxla's survey of 106 sites only 14% had a CSP. "
         "It is hard to write, because a mistake breaks the site. So SaytYoxla looks not only at whether a CSP exists but also at its quality (weak rules such as “unsafe-inline” give a warning). 4 points.</p>"),
        ("x-frame-options", "What are clickjacking, X-Frame-Options and frame-ancestors?", "clickjacking framing iframe x-frame-options frame-ancestors",
         "<p>In a clickjacking attack, the attacker places your site invisibly inside their own page (an iframe). The person thinks they are pressing “claim your prize”, but they are really pressing “pay” or “delete” on your site. "
         "The <b>X-Frame-Options</b> header, or <b>frame-ancestors</b> in the CSP, forbids opening the site inside other sites. 5 points in SaytYoxla.</p>"),
        ("nosniff", "What is X-Content-Type-Options (nosniff)?", "nosniff content type sniffing header mime",
         "<p>A browser sometimes “guesses” a file's type on its own. An attacker can hide a script inside a file that looks like an image and make the browser run it. The <i>nosniff</i> header stops the guessing: the file is treated as the type it is declared to be. 4 points.</p>"),
        ("referrer-policy", "What is Referrer-Policy?", "referrer policy header referer",
         "<p>When someone moves from your site to another, the browser passes on the previous address, saying “I came from here”. That address sometimes holds private information (an order number, a token). This header limits what is passed on. 2 points.</p>"),
        ("cookie-qoruma", "What is a cookie, and how is it protected?", "cookie secure httponly samesite session",
         "<p>A cookie is a small text note kept in the browser; it is how a site recognises you after you log in. If a cookie is stolen, the attacker can log in as you. That is why three flags are needed: "
         "<b>Secure</b> (sent over HTTPS only), <b>HttpOnly</b> (JavaScript cannot read it, which protects against XSS) and <b>SameSite</b> (not sent with requests coming from another site, which protects against CSRF). 5 points in SaytYoxla. "
         "Note: SaytYoxla itself uses no cookies.</p>"),
        ("server-versiya", "What is server version disclosure?", "server header x-powered-by version disclosure php nginx apache",
         "<p>Some servers write “I am Apache 2.2.15” or “I run PHP 5.6” in every answer. For an attacker this is a ready-made map: they look up the known weakness of that version straight away. Hiding the version is not protection on its own, but it is a good habit not to help an attacker. 6 points.</p>"),
        ("qarisiq-mezmun", "What is mixed content?", "mixed content http image script",
         "<p>The page opens over HTTPS, but an image or script inside it loads over HTTP. Then the padlock breaks, and that part can be changed from outside. The fix: call every resource with <i>https://</i>. 5 points.</p>"),
    ]),
    ("3. E-mail and domain protection", [
        ("eposta-saxta", "What is fake e-mail (spoofing)?", "spoofing fake mail phishing email",
         "<p>When the e-mail protocol was designed, nobody checked who the sender was. So anyone can write a message in the name of <i>info@your-site.az</i>. Fraudsters use this to write to your customers: “send the payment to this account”. "
         "SPF, DKIM and DMARC exist to stop exactly this. All three are written as TXT records in DNS.</p>"),
        ("spf", "What is SPF?", "sender policy framework spf txt email",
         "<p>SPF is a list for a domain: “only these servers may send mail in this domain's name”. The receiving server looks at which server the message came from and treats it with suspicion if it is not on the list. "
         "The end of the record matters: <i>-all</i> (reject what is not on the list) and <i>~all</i> (treat it as suspicious) work, while <i>?all</i> and <i>+all</i> protect nothing in practice. 10 points in SaytYoxla.</p>"),
        ("dkim", "What is DKIM?", "domainkeys identified mail dkim signature selector",
         "<p>DKIM puts a digital signature on every message. The receiving server checks the signature against the public key in DNS and confirms the message was not changed on the way. "
         "DKIM uses a name called a “selector”, and every e-mail service has its own (google, selector1, k1, mail and so on). For this reason SaytYoxla looks at the common names; if none is found, that does not mean “there is no record”, it may simply be written under another name. So DKIM does not count towards the score and is shown for information only.</p>"),
        ("dmarc", "What is DMARC?", "dmarc p=none quarantine reject email rua",
         "<p>DMARC is the decision that sits on top of SPF and DKIM: “what should be done with a message that fails the check?” There are three choices: <b>p=none</b> (do nothing, only send a report), <b>p=quarantine</b> (put it in the spam folder) and <b>p=reject</b> (do not show it at all). "
         "The right way is this: first you write <i>p=none</i> and read the reports; if everything is in order, you move to <i>quarantine</i> and then <i>reject</i>. Otherwise your own legitimate mail can get lost too. "
         "In SaytYoxla's survey of 106 sites, 58% enforced DMARC (quarantine/reject). 8 points; <i>p=none</i> gives half.</p>"),
        ("mx", "What is an MX record?", "mx mail exchange email server dns",
         "<p>An MX record says which server receives the domain's e-mail. If you use Google Workspace, for example, the MX records point to Google's servers.</p>"),
    ]),
    ("4. Kinds of attack", [
        ("xss", "What is XSS (Cross-Site Scripting)?", "xss cross site scripting script inject reflected stored",
         "<p>In XSS, an attacker places their own harmful script on a page of your site. In the browser of everyone who opens that page, the script runs in your site's name: it can steal cookies, change forms and send people to other sites. "
         "It usually happens when a site shows text the user typed (a search, a comment, a parameter in the address) on the page without cleaning it. "
         "In <b>reflected</b> XSS the script is inside the address and hits only the person who presses that link. In <b>stored</b> XSS the script is kept in the database (in a comment, for example) and hits everyone who opens the page. "
         "Protection: always clean (escape) user text and use a CSP.</p>"),
        ("sql", "What are SQL and a database?", "sql database query mysql postgres",
         "<p>A database is the site's store of information: users, orders, products. SQL is the language for asking the database questions. For example: “find the user with this address”.</p>"),
        ("sql-injection", "What is SQL injection?", "sql injection sqli database attack parameter",
         "<p>When a site puts the text a user typed straight into an SQL query, an attacker can write their own SQL command inside that text and the site runs it. As a result the attacker can read the whole list of users, delete it or log in as an administrator. "
         "This attack has been known for decades and is still among the most dangerous. Protection: write the query as a “parameterised” one (a prepared statement); most ready-made libraries do this automatically.</p>"),
        ("csrf", "What is CSRF?", "csrf cross site request forgery",
         "<p>In CSRF, an attacker makes you carry out an action you did not want on a site where you are logged in. For example, you log in to your bank and look at a harmful page in another tab, and that page quietly sends a “transfer money” request. "
         "Protection: a random token in every form and the <i>SameSite</i> flag on the cookie.</p>"),
        ("fishinq", "What is phishing?", "phishing fake site password deception",
         "<p>Phishing is an attempt to get your password or card details with a fake page or message that looks like a real site or bank. The signs: an urgent demand, a strange address, a domain that is not quite right. "
         "SPF and DMARC reduce fake e-mail, and HTTPS proves that your site is not a fake.</p>"),
        ("brute-force", "What is a brute-force attack?", "brute force password guessing login attack",
         "<p>The attacker tries thousands of passwords one after another in a login form. Protection: a long password that is not reused, a limit on login attempts (a rate limit) and two-step verification (2FA).</p>"),
        ("ddos", "What is DDoS?", "ddos dos attack load site down",
         "<p>In a DDoS attack, requests are sent to your site from thousands of devices at once and the server gives up. For small sites a CDN (Cloudflare, Vercel) usually absorbs this by itself. SaytYoxla sets limits too, so that the checker itself cannot be abused.</p>"),
        ("malware", "What is malware?", "malware harmful software virus hack hacked",
         "<p>On a hacked site, the attacker often plants hidden harmful code: it sends visitors to other sites, shows adverts or steals card details. The signs: the site suddenly slows down, Google shows a “this site may be harmful” warning, unknown pages appear. "
         "The main causes are old plugins, weak passwords and software that is not updated.</p>"),
        ("prompt-injection", "What is prompt injection?", "prompt injection ai artificial intelligence llm agent provguard",
         "<p>Prompt injection is an attack on software built on artificial intelligence (an LLM): the attacker writes a hidden command addressed to the AI inside a document, an e-mail or a web page (“forget the earlier instructions and ...”). The AI may take it as the user's own command and do something nobody asked for. "
         "If you are building an AI assistant or a chatbot, this risk applies to you as well. We have a separate open-source tool on the subject, ProvGuard (<a href=\"https://provguard.vercel.app\" rel=\"noopener\">provguard.vercel.app</a>), "
         "and an article that explains it: <a href=\"https://ayfar.dev/articles/provguard.html\" rel=\"noopener\">ayfar.dev/articles/provguard.html</a>.</p>"),
    ]),
    ("5. Google and speed", [
        ("seo", "What is SEO?", "seo search engine google ranking optimisation optimization",
         "<p>SEO is the work that helps a site appear higher in Google: a proper title and description, speed, a page that fits a phone, useful content. "
         "To be honest: SaytYoxla checks the technical basics of SEO, but it does not guarantee a ranking. Getting to the top of Google also depends on content, competition and time.</p>"),
        ("title-description", "What are the title and the meta description?", "title heading meta description google result",
         "<p>The <b>title</b> is the blue heading shown in the browser tab and in a Google result (ideally 10–70 characters). The <b>meta description</b> is the short explanation under the result (ideally 50–170 characters). "
         "Every page should have its own title and description. Without them Google picks some text by itself and fewer people click. SaytYoxla checks each of them.</p>"),
        ("h1", "What is an H1 heading?", "h1 heading page",
         "<p>The H1 is the page's main heading; every page should have exactly one. Google and screen readers use it to understand what the page is about.</p>"),
        ("viewport", "What are the viewport and mobile-friendliness?", "viewport mobile phone responsive meta",
         "<p>The viewport tag tells a phone: “show the page at the width of the screen”. Without it the phone opens the site at computer size and shrinks it, and it cannot be read. Google takes mobile-friendliness into account in ranking. 8 points in SaytYoxla.</p>"),
        ("robots-sitemap", "What are robots.txt and sitemap.xml?", "robots txt sitemap xml search robot crawler index",
         "<p><b>robots.txt</b> tells search robots which parts they may and may not enter. <b>sitemap.xml</b> is the list of all the site's pages; it is how you tell Google “these are my pages”. "
         "If robots.txt closes everything by mistake, the site will not appear in Google at all.</p>"),
        ("noindex", "What are noindex and indexing?", "noindex index indexing google not shown",
         "<p>Indexing is Google adding a page to its own database. If the page carries a <i>noindex</i> tag, Google does not add it and it does not appear in search. "
         "A noindex put in while the site was being built is often forgotten after launch. This is the most common answer to “why is my site not in Google?”. 6 points.</p>"),
        ("canonical", "What is a canonical link?", "canonical link duplicate page",
         "<p>The canonical tag tells Google “this is the main address of this page”. It is needed so that Google does not mix up the same page opening at several addresses (with and without www).</p>"),
        ("lang-og", "What are the page language and the social card (Open Graph)?", "lang language og open graph social card share whatsapp",
         "<p>The <b>lang</b> tag states the page's language (az, en, ru); the browser's offer to translate and screen readers use it. "
         "<b>Open Graph (og)</b> tags set the image and title that appear when the link is shared in WhatsApp, Instagram or LinkedIn. Without them the link looks empty and untrustworthy. 2 points each.</p>"),
        ("cavab-vaxti", "What are server response time and page weight?", "speed response time ms html size weight slow images cache script",
         "<p>People leave a slow site. SaytYoxla measures the server's response time: under 1500 ms is good, up to 4000 ms is a warning, more is bad (8 points). "
         "The HTML size is measured too: under 300 KB is good, up to 1000 KB is a warning (4 points).</p>"
         "<p>Then the files the page names are asked for once each: scripts, stylesheets and images. Together with the HTML they are the <b>full page weight</b>: under 2 MB is good, up to 5 MB is a warning, more is bad (5 points). "
         "An image over 500 KB counts as heavy (3 points); four or more scripts at the top of the page that hold back the first display give a warning (2 points); so do the site's own files when most of them are sent without browser caching (2 points). "
         "Files that a script adds later are not seen, because the page is not run in a browser.</p>"),
        ("sixilma-http2", "What are compression (gzip, brotli) and HTTP/2?", "gzip brotli compression http2 http/2 speed protocol",
         "<p><b>Compression</b> means the server shrinks the page before sending it (gzip or brotli); the browser unpacks it by itself. Text gets 3–5 times smaller, and on a weak connection the difference is felt at once. "
         "SaytYoxla looks at whether the server's answer is compressed (3 points); it does not ask this of a page smaller than 1400 bytes.</p>"
         "<p><b>HTTP/2</b> is the newer version of the rules a browser and a server talk by: images, styles and scripts arrive over one connection at the same time. In the old HTTP/1.1 they wait in a queue. "
         "On most hosting, HTTP/2 can be turned on for free in the panel (2 points).</p>"),
        ("alt-schema", "What are image descriptions (alt) and Schema.org?", "alt image description img schema json-ld structured data localbusiness",
         "<p><b>alt</b> is a short text description of an image: <i>&lt;img src=\"...\" alt=\"Red sofa\"&gt;</i>. Google does not see the image, it reads this text; the software used by people who have trouble seeing reads it aloud too. "
         "A purely decorative image gets an empty <i>alt=\"\"</i>. If any image has no description, SaytYoxla gives a recommendation (2 points).</p>"
         "<p><b>Schema.org</b> (JSON-LD) is a small block of information added to the page that people do not see: the business's name, address, phone and opening hours. "
         "Google reads it and recognises the business more precisely (1 point).</p>"),
        ("core-web-vitals", "What are Core Web Vitals?", "core web vitals lcp cls inp lighthouse pagespeed",
         "<p>Core Web Vitals are three measurements Google uses for page experience: when the main content appears (LCP), how much the page “jumps” while loading (CLS) and how fast it answers a tap (INP). "
         "An honest note: SaytYoxla does not measure these; that needs the page to load fully in a browser. You can check them in Google's PageSpeed Insights or Lighthouse.</p>"),
    ]),
    ("6. How SaytYoxla works", [
        ("bal-hesablanma", "How is the score calculated?", "score calculation grade a b c d f cap",
         "<p>SaytYoxla runs 34 checks; 32 of them carry points (TLS and DKIM are for information only). Every check has a weight: the heaviest are HTTPS (20), the certificate (15) and SPF (10), then smaller ones from 8 points down. The weights add up to 163 and are converted to 100. "
         "A failed check loses its whole weight, a warning half of it. A check that could not be made is left out and costs nothing.</p>"
         "<p>Grades: 90 and above is A, 75 and above B, 60 and above C, 40 and above D, below that F. There are caps as well: if HTTPS does not work the score cannot rise above 39, and if the certificate is not valid, above 59. "
         "If 4 or more of the five core protections (redirect, HSTS, clickjacking, nosniff, CSP) have a problem, the score cannot rise above 74; with 2 of them, above 89. So weak security cannot be “covered up” by other good results.</p>"),
        ("nezaman-yoxlayir", "What does SaytYoxla check, and what does it not?", "checks does not check limit limitation audit",
         "<p><b>It checks:</b> HTTPS, the certificate, headers, cookie flags, SPF/DMARC/DKIM, speed and page weight, mobile-friendliness and the basic tags for Google, that is, everything anyone can see from outside. All without harming the site: the home page, the files it loads (scripts, styles, images), robots.txt and sitemap.xml are opened once.</p>"
         "<p><b>It does not check:</b> the site's internal code, the inside of the server, passwords, the database or the logic of the software. This is not a full security audit. A high score does not mean “the site is completely secure”, and a low score does not mean “the site has been hacked”.</p>"),
        ("deep-scan", "What are the deep analysis and ownership proof?", "deep scan analysis ownership proof dns file port sql xss check",
         "<p>The deep analysis looks at the site's outer surface: subdomains, DNS, old software versions, exposed files and ports. Some parts run only after you prove the site is yours (with a DNS record or a file); looking for exposed files on someone else's site would not be right. "
         "After the proof, address parameters are tested for SQL injection and XSS with read-only, harmless requests (for example a single quote and an <i>AND 1=1</i> / <i>AND 1=2</i> comparison). Nothing is deleted, changed or written. The content of a file or key that is found is neither shown nor stored.</p>"),
        ("netice-oxu", "How do I read the result?", "result report read red yellow green priority",
         "<p>In the report every check gets one of three colours: green (in order), yellow (a warning) and red (a problem). Look at the red ones first: they lower the score the most. "
         "Under every problem it says what to do; showing this to the developer who built the site is enough. The result is a picture of that moment only: check again when the site changes.</p>"),
        ("mexfilik-xulase", "What information does SaytYoxla keep?", "privacy cookie tracking stored ip",
         "<p>It does not ask for your name or phone, and there are no cookies or tracking scripts. An e-mail address is needed only if you choose ongoing watching of your site yourself. The checked address and its result stay for up to 10 minutes to speed up a repeat check, and the IP address stays for up to 1 day in the counter that limits abuse. "
         "More: <a href=\"/en/privacy/\">Privacy</a>.</p>"),
    ]),
    ("7. Practical advice for protecting a site", [
        ("yenileme", "Updates and old software", "update plugin wordpress old version weakness vulnerability cve",
         "<p>In a large share of hacked sites the cause is old software (WordPress, plugins, libraries). Weaknesses are announced publicly, and robots search millions of sites for them automatically. Do not put off updates, and remove the plugins you do not use. Known weaknesses are recorded under a <b>CVE</b> number.</p>"),
        ("parol-2fa", "Passwords and two-step verification (2FA)", "password 2fa two step manager",
         "<p>A separate long password for every service, a password manager, and 2FA on admin panels. Protect the domain company, hosting and e-mail accounts above all: if they are taken over, the attacker owns the site and the mail.</p>"),
        ("backup", "Backups", "backup copy restore",
         "<p>If the site is hacked or deleted, or the server fails, a backup saves you. You need one that is automatic, kept in a separate place and restored as a test from time to time.</p>"),
        ("cdn-waf", "What are a CDN and a WAF?", "cdn waf cloudflare firewall protection",
         "<p>A <b>CDN</b> keeps copies of the site in different parts of the world and serves each visitor from a server near them; it makes the site faster. A <b>WAF</b> (Web Application Firewall) is a shield in front of the site that filters harmful requests. Services such as Cloudflare offer both, even on the free plan.</p>"),
        ("security-txt", "What is security.txt?", "security txt weakness vulnerability report contact",
         "<p>The file <i>/.well-known/security.txt</i> tells a security researcher who to write to when they find a weakness. It is small, but it is the mark of a serious site.</p>"),
    ]),
]
