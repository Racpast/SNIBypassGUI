# SNIBypassGUI Proprietary License

**Version 2.0 — Effective Date: August 24, 2026**

Copyright © 2026 Racpast. All rights reserved.

> **Read this first.** This is **not** an open-source license. The source code of
> SNIBypassGUI is published for **transparency and security verification only**.
> Publication is not a grant of rights. Except for the narrow permissions in
> Section 5, every right in the Software is reserved to the Author, including the
> rights to compile, modify, reuse, extract, and redistribute.

---

## 1. PREAMBLE AND PURPOSE

SNIBypassGUI (the "Software") is the proprietary work of **Racpast** (the
"Author"). It is not, and has never been, dedicated to the public domain, and no
part of it is offered under a free or open-source license except where Section 3
expressly says so for a third-party component.

The Author publishes the Software's source code for one reason only: the Software
intercepts DNS traffic and operates a local TLS-terminating proxy, and users are
entitled to verify for themselves that it does what it claims and nothing more.
Source availability is a **transparency measure**, not a licensing model. Nothing
in the act of publication may be construed as consent to compile, modify, reuse,
or redistribute the Software or any part of it.

The Software embodies substantial original authorship beyond its source code:

1. **An original compilation.** The Payload Data is a curated body of
   domain-to-address mappings, SNI-handling configurations, and connection
   methodologies, each entry established and verified through months of
   systematic empirical testing of individual domains and subdomains. This
   compilation is a protectable work of authorship under 17 U.S.C. § 103.

2. **Original selection, coordination, and arrangement.** Not every domain
   functions with every address, and not every domain tolerates the same SNI
   treatment. Determining which pairings work, associating each with the correct
   port, connection method, and SNI parameters, and organizing the result into
   the Software's configuration hierarchy required creative judgment that is
   independent of any individual underlying fact.

3. **Original expression in the configuration architecture.** The directory
   structure, the decomposition of configuration into reusable units, the naming
   scheme, and the object-oriented organization of the nginx configuration tree
   are creative choices among many workable alternatives.

The Author expressly reserves all rights not granted in this License.

---

## 2. DEFINITIONS

**2.1 "Software"** means the SNIBypassGUI application and all material in the
Author's SNIBypassGUI repository and Binary Releases, including the Source Code,
the Payload Data, the user interface, build tooling, and documentation. "Software"
**excludes** the Third-Party Components identified in Section 3 and everything
located in the `third_party/` directory, which are governed solely by their own
licenses.

**2.2 "Source Code"** means the human-readable source files authored by the
Author, together with build scripts, configuration templates, and resources used
to produce the Software.

**2.3 "Payload Data"** means, subject to the exclusions in Section 2.1, all
operational data distributed with or as part of the Software, in any format and
at any location, including nginx configuration files and fragments, supported-site
lists, domain-to-address mappings, DNS rule sets, resolver and connection
definitions, and any data file consumed by the Software at runtime or delivered
through its update mechanism.

**2.4 "Binary Release"** means any compiled distribution of the Software
published by the Author, together with its payload directory and update
manifests.

**2.5 "Derivative Use"** means any use of the Software's Source Code, Payload
Data, protected expression, structure, or organization in another work, whether by
copying, transcription, translation into another language or format, mechanical
transformation, parsing, extraction, or the production of a work substantially
similar to any of them.

**2.6 "Competing Project"** means any software, service, dataset, or distribution
whose primary or substantial function overlaps that of the Software, including SNI
routing or manipulation, DNS interception or redirection, local proxy automation
for reaching name-restricted services, and comparable network traffic
manipulation.

**2.7 "Commercial Use"** means use of the Software (a) by or on behalf of a
for-profit entity in the conduct of its operations; (b) in exchange for payment or
other consideration; (c) to support any product or service offered to third
parties for a fee; or (d) in a production, workplace, or revenue-generating
environment. Use by an individual, on equipment that individual owns or controls,
for that individual's own purposes, is not Commercial Use regardless of that
individual's employment.

**2.8 "Personal Use"** means use by a single natural person, on equipment that
person owns or controls, for that person's own purposes and not for the benefit of
any organization. Where this License refers to a "non-commercial user," it means
a person whose use is confined to Personal Use.

**2.9 "GitHub Baseline Rights"** means the rights that GitHub, Inc.'s Terms of
Service confer on other users of that platform by operation of the Author's
decision to make the repository public, as described in Section 4.

**2.10 "Restricted Parties"** has the meaning given in Section 8.

**2.11 "You"** means the natural person or legal entity exercising any right or
performing any act addressed by this License.

---

## 3. THIRD-PARTY COMPONENTS

This Section governs before all others. Nothing elsewhere in this License limits,
conditions, or purports to restrict any right you hold in a Third-Party Component
under that component's own license. Where this License would conflict with a
Third-Party Component's license as applied to that component, that license
controls and this License yields.

**3.1 WinDivert.** The Software uses WinDivert, copyright © basil
(basil@reqrypt.org), available under your choice of LGPL v3, GPL v3, or GPL v2.
The complete license texts — including the GPL v3 text on which LGPL v3 depends —
are in `third_party/windivert/LICENSE` in the repository and in
`licenses/windivert/` in every Binary Release.

**3.2 No combined work.** SNIBypassGUI links against no part of WinDivert. The
executable resolves every WinDivert entry point at runtime by `LoadLibrary` and
`GetProcAddress`; the WinDivert header contributes only type, structure, and
constant definitions and no function bodies or import stubs. `WinDivert.dll` and
`WinDivert64.sys` are distributed as unmodified, independent, separately
replaceable files. The Software is therefore a work that *uses* the library at
arm's length rather than a Combined Work under LGPL v3 § 4, and the obligations
that section imposes on Combined Works do not attach to the Software.

**3.3 Right to replace.** You may at any time replace the WinDivert files in an
installation with a modified or differently versioned build of WinDivert. Doing so
is expressly permitted by this License, is not a modification of the Software, and
is not a circumvention of any protection mechanism for the purposes of Section 6 or
of the end-user agreement. The Author provides no support for, and makes no
warranty regarding, an installation running a replaced WinDivert.

**3.4 nginx.** Binary Releases include a build of nginx compiled by the Author
from modified nginx source code. nginx is copyright © Igor Sysoev and Nginx, Inc.,
and is licensed under the 2-clause BSD license, which permits modification and
redistribution. The nginx license is reproduced at
`resources/payload/licenses/nginx/LICENSE` in the repository and at
`licenses/nginx/` in every Binary Release. The binary is statically linked against
OpenSSL (Apache License 2.0) and PCRE2 (BSD). The Author's modifications to nginx
are governed by this License; the original nginx code, OpenSSL, and PCRE2 remain
under their respective licenses.

**3.5 sni-gate.** `data/sni-gate.exe` is a separate work of the Author, published
independently under the MIT License and the Apache License 2.0 at the recipient's
option. Nothing in this License narrows the rights you hold in that binary or its
source under either of those licenses. Its presence in a Binary Release neither
extends this License to it nor extends its licenses to anything else.

**3.6 Other components.** Any additional third-party material distributed with the
Software carries its own license text at `licenses/` in the Binary Release. Where
a component is present but its license is not reproduced, the omission is
inadvertent, that component remains under its own license, and the Author will
correct the omission on notice.

**3.7 Redistributor obligations.** In any case where a Third-Party Component's
license permits you to redistribute it, you must carry forward the license text,
copyright notices, and any required attribution or source-availability notices for
that component. This obligation exists under those licenses independently of this
License, is not created by it, and survives the termination of your rights under
Section 12 without limitation.

---

## 4. GITHUB PLATFORM RIGHTS

**4.1 What the platform grants.** Because the Author has made the repository
public, GitHub's Terms of Service § D.5 grant every other GitHub user a
nonexclusive, worldwide license to **use, display, perform, and reproduce (by
forking)** the repository's contents **through the Service as permitted by
GitHub's functionality**. The Author acknowledges these rights, does not attempt to
revoke them, and confirms that no term of this License is intended or shall be
construed to reduce them below that baseline.

**4.2 Forking is permitted.** You may fork the repository on GitHub. A fork made
and kept within GitHub in a repository you control is an exercise of the GitHub
Baseline Rights and is not a violation of Section 6, notwithstanding that a public
fork is necessarily a publicly visible copy. This permission covers the existence
and continued hosting of the fork itself. It does not permit compiling the fork,
modifying it, publishing releases from it, extracting Payload Data from it, or
mirroring it outside GitHub — each of those is a separate act governed by Sections
5 and 6.

**4.3 What the platform does not grant.** The GitHub Baseline Rights are limited
to the Service. They do not include downloading a copy outside GitHub's web
interface, cloning to local storage, compiling, modifying, redistributing outside
GitHub, or any Derivative Use. Any such right must come from Section 5 of this
License or from a separate written grant by the Author.

**4.4 Deletion.** Consistent with GitHub's Terms of Service § D.3, the Author's
grants to GitHub and to other users end when the Author removes the content,
except as to forks already made.

---

## 5. RIGHTS GRANTED BY THE AUTHOR

Subject to your compliance with this License, and in addition to the GitHub
Baseline Rights, the Author grants you the following — and only the following.

**5.1 Right to obtain and run Binary Releases.** You are granted a limited,
personal, revocable, nonexclusive, non-transferable, non-sublicensable license to
download an official Binary Release from a distribution channel operated by the
Author, to install it on equipment you own or control, and to run it in executable
form for **Personal Use**. This right is subject to your acceptance of the
end-user agreement accompanying that Binary Release.

**5.2 Right to obtain the Source Code for inspection.** You are granted a
limited, personal, revocable, nonexclusive, non-transferable,
non-sublicensable license to obtain one copy of the Source Code — by download,
clone, or fork — and to read, review, and analyze it for the purpose of verifying
what the Software does, auditing it for security defects, and satisfying yourself
as to its behavior before running it. This right is granted by the Author, not by
GitHub, and it exists independently of the GitHub Baseline Rights described in
Section 4.

**5.3 What Section 5.2 permits.** Under Section 5.2 you may read the code; run
static analysis, linters, and other read-only tooling over it; view it in an
editor, IDE, or diff tool; retain your copy for as long as your rights under this
License remain in effect; and describe in your own words what you found.

**5.4 What Section 5.2 does not permit.** Section 5.2 confers **no** right to
compile, build, execute, modify, adapt, translate, port, reuse, redistribute, or
make any Derivative Use of the Source Code, and no right to extract or reuse the
Payload Data. Reading is the entire extent of the grant.

**5.5 Security research and disclosure.** You may study the Software for security
research and you may publish your findings. The Author does not require your
silence and does not condition Section 5.2 on advance notice, embargo, or
coordinated disclosure. The Author requests — as a courtesy and not as a condition
— that a security defect affecting users be reported to the Author before public
disclosure so that a fix can be shipped. Publishing a vulnerability report,
including the minimum excerpt of code or configuration necessary to demonstrate the
defect, is a fair use and is not a violation of Section 6.

**5.6 Academic and journalistic reference.** You may quote and cite the Software,
including short excerpts of code or configuration, for commentary, teaching,
scholarship, review, and news reporting. This Section confirms that such uses are
outside the scope of Section 6 and does not purport to enlarge or narrow fair use
under 17 U.S.C. § 107.

**5.7 No other rights.** No right, title, interest, or license is granted by
implication, estoppel, exhaustion, course of conduct, acquiescence, or the
Author's failure to act. All rights not expressly granted in Sections 4 and 5 are
reserved.

**5.8 Commercial use requires a separate agreement.** Sections 5.1 and 5.2 do not
authorize Commercial Use. Any Commercial Use requires a prior separate written
license signed by the Author.

**5.9 Prior versions.** Earlier releases of the Software distributed by the Author
under the GNU Affero General Public License v3 remain available under that license
according to its own terms. This License applies to the Software as published under
it and does not purport to withdraw, retroactively relicense, or otherwise affect
any right any person acquired in a previously AGPL-licensed release. Nothing in
those earlier grants extends to this version, to its Source Code, or to its
Payload Data, none of which was ever published under the AGPL.

---

## 6. RESTRICTIONS

Except as Sections 3, 4, and 5 expressly permit, and except where a right is
granted to you by law notwithstanding contract, you may not do any of the
following without the Author's prior written permission.

**6.1 Building and running from source.** Compile, assemble, build, link, or
otherwise produce an executable from the Source Code; or execute any build script,
CMake preset, or CI workflow in this repository for the purpose of producing a
binary.

**6.2 Modification.** Modify, adapt, translate, port to another language or
platform, refactor, or create a derivative work of the Source Code or the Payload
Data.

**6.3 Reuse of code.** Copy, transcribe, or incorporate any portion of the Source
Code into any other work, whether verbatim, translated, paraphrased, or
mechanically transformed.

**6.4 Extraction of Payload Data.** Extract, harvest, scrape, parse, transcribe,
convert, reformat, or otherwise remove the Payload Data or any substantial portion
of it from the Software, whether by hand or by any program, script, or tool
written for that purpose or adapted to it. **This prohibition applies with equal
force to the Payload Data as it exists in the repository, in a fork, in a Binary
Release, in an installed copy, in an update package, and in memory at runtime.**
Writing, publishing, or using a parser, converter, or scraper whose purpose or
effect is to translate the Payload Data into another program's format is itself a
violation of this Section and an act of infringement, independent of what is done
with the output.

**6.5 Use of Payload Data elsewhere.** Use, publish, redistribute, sublicense, or
incorporate the Payload Data or any substantial portion of it in any other
software, service, dataset, configuration set, or distribution — **most
particularly in any Competing Project** — whether attributed or not, whether the
result is offered free or for a fee, and whether the data is reproduced verbatim or
converted into another format.

**6.6 Reuse of the compilation and its arrangement.** Reproduce the selection,
coordination, or arrangement of the Payload Data, or the structure, decomposition,
naming scheme, or organization of the configuration tree, in any other work. This
Section restricts reuse of the Author's **expression**. It does not restrict the
underlying facts as such, and nothing in it prevents you from independently
determining the same facts by your own testing and measurement.

**6.7 Machine learning and datasets.** Incorporate the Source Code or the Payload
Data into a training corpus, fine-tuning dataset, evaluation set, embedding index,
retrieval corpus, or knowledge base for a machine learning system. The Author's
grant to GitHub under its Terms of Service § D.4 is a grant to GitHub alone and
confers nothing on you.

**6.8 Redistribution.** Distribute, publish, mirror, host, sublicense, sell, rent,
lease, lend, or transfer the Software, the Source Code, the Payload Data, or any
Binary Release to any third party, or make any of them available for download
outside the Author's own distribution channels. **This does not apply to a GitHub
fork made under Section 4.2.**

**6.9 Repackaging.** Publish a modified, rebranded, recompiled, or repackaged build
of the Software; publish a release, installer, archive, or package containing the
Software or the Payload Data; or bundle any of them with other software.

**6.10 Attribution integrity.** Remove, obscure, or alter any copyright notice,
license text, attribution, or proprietary legend; misrepresent the origin or
authorship of the Software; or represent your work as the Software, as a version or
edition of it, or as endorsed by or affiliated with the Author.

**6.11 Misdirected attribution.** Present a link, citation, or reference that
purports to credit or point to the Software or the Author while in fact directing
the reader to a different project, repository, or distribution. Where such conduct
is likely to cause confusion as to origin, sponsorship, or affiliation, it is
actionable under § 43(a) of the Lanham Act, 15 U.S.C. § 1125(a), independently of
copyright.

**6.12 Circumvention of technical measures.** Circumvent, disable, or defeat any
technical measure the Author employs to control access to the Software or to
protect the Payload Data, including update manifest verification and integrity
checks. Replacing a Third-Party Component under Section 3.3 is not circumvention.

**6.13 Reverse engineering.** Decompile, disassemble, or reverse engineer any
binary distributed as part of the Software, **except** (a) to the extent necessary
to achieve interoperability, where and as that activity is permitted by applicable
law notwithstanding any contractual prohibition; (b) for the security research
permitted by Section 5.5; (c) as required to exercise a right you hold under a
Third-Party Component's license, including any right under LGPL v3 to debug
modifications to that component; and (d) as otherwise permitted by law
notwithstanding this License. This Section and Section 6.1 are the complete
statement of the Author's position on these activities; no other provision of this
License restricts them further.

**6.14 Facilitation.** Direct, induce, fund, or knowingly assist another person in
doing anything this Section prohibits, or provide a tool, script, service, or
instruction set whose principal purpose is to accomplish it.

**6.15 Concealed use.** Perform any act this Section prohibits and then omit, hide,
or misstate it — including by placing extracted Payload Data only in release
artifacts while keeping it out of a public source tree, committing it without
history, or attributing it to independent research. Concealment does not cure a
violation; it is evidence of willfulness under 17 U.S.C. § 504(c)(2).

**6.16 What this Section does not restrict.** For the avoidance of doubt, nothing
in this Section restricts: reading the Source Code under Section 5.2; running an
official Binary Release under Section 5.1; forking on GitHub under Section 4.2;
publishing security findings under Section 5.5; quoting or citing under Section
5.6; independently determining any fact by your own measurement; implementing SNI
routing, DNS interception, or any other **idea, method, technique, or functional
concept**, which 17 U.S.C. § 102(b) places outside copyright altogether; or
exercising any right conferred by law that a contract cannot waive.

---

## 7. OWNERSHIP OF THE PAYLOAD DATA

**7.1 Compilation copyright.** The Payload Data is a compilation under 17 U.S.C.
§ 101 and is protected under § 103. The Author's claim is to the **selection,
coordination, and arrangement** of its contents and to the original expression in
its organization — not to any individual address, domain name, or protocol
parameter as an isolated fact.

**7.2 Origination.** Each entry in the Payload Data was established by the Author
through systematic empirical testing conducted over a period of months, mapping
individual domains and subdomains against candidate addresses to determine which
combinations function and by what connection method. The supported-site
composition further reflects the Author's editorial judgment exercised in response
to the requirements of the Software's user community. The compilation is the record
of that work.

**7.3 Originality of the selection.** The set of workable pairings is not
mechanically derivable from public data. Many domains fail with addresses that
resolve for them; many require particular SNI treatment; many function only over a
specific method or port. Determining which of the many possible combinations
function, and discarding those that do not, is a selection made from a much larger
candidate space, and its result is not an obvious or inevitable arrangement of
facts.

**7.4 Independent creation.** Nothing in this Section restrains anyone who
independently performs their own measurement and reaches their own conclusions.
Independent creation is a complete defense to infringement, and the Author does not
assert otherwise. What this License addresses is **copying** — taking the benefit
of the Author's compilation without doing the work — including copying accomplished
by mechanically transforming the Author's files into another format.

**7.5 Evidence of copying.** A substantial correspondence between the Author's
compilation and another body of data, in the pairings selected, in their
arrangement, or in patterns characteristic of the Author's work, is probative of
copying. The Author maintains dated records of the compilation's development and
reserves all evidentiary use of them.

**7.6 Not a trade secret claim.** The Author publishes the Payload Data and does
not assert that it is secret. The claim asserted here is copyright in an original
compilation, together with the contractual restrictions in Section 6.

---

## 8. RESTRICTED PARTIES

**8.1 Basis.** Section 5 grants rights personally and revocably. The Author
declines to extend those grants to persons who have already taken the Author's work
without permission. This Section identifies those persons by reference to their
**conduct** and to the accounts through which that conduct was carried out.

**8.2 Conduct-based exclusion.** You are a Restricted Party, without regard to
identity, if you have done or later do any of the following:

(a) extracted, parsed, converted, or reproduced the Payload Data or any substantial
portion of it for use outside the Software, in violation of Section 6.4 or 6.5, or
in violation of the AGPL v3 terms applicable to any earlier release from which it
was taken;

(b) published, distributed, or shipped in any artifact — including a release
binary, archive, or installer, whether or not the corresponding material appears in
a public source tree — data derived from the Payload Data without the attribution
and licensing that the applicable license required;

(c) presented a link, credit, or citation naming the Software or the Author that in
fact directed readers to a different project, repository, or distribution, in
violation of Section 6.11;

(d) obtained access to the Author's user community under a false or concealed
identity, or after having been excluded from it, in order to collect user
requirements, feature requests, or other community output for use in a Competing
Project;

(e) knowingly assisted, directed, or induced another person in any of the
foregoing.

**8.3 Named accounts and identifiers.** The Author's records identify the following
as accounts and identifiers through which conduct described in Section 8.2 was
carried out. Each is listed as an **identifier of a Restricted Party**, and the
exclusion attaches to the person or persons operating it:

(a) QQ accounts **1175034206** and **3989623715**, and any person who created,
controls, or operates either;

(b) any GitHub account that has at any time used the username **coolapijust**,
**mechrevo**, **dongzheyu**, **lzpls**, or **JetCPP-dongle**, and any person who
created, controls, or operates such an account;

(c) the repository **snishaper**, its forks, and its successors under any name, and
any person who created, maintains, or has at any time maintained any of them;

(d) the **snishaper** organization and any person who is or has been a member of
it, whether that membership is public or private;

(e) any alternate, successor, or additional account operated by a person identified
under (a) through (d), including an account created after a public statement of
withdrawal from a project, and including any account operated for the purpose of
continuing conduct described in Section 8.2 under a different name.

**8.4 Effect.** A Restricted Party has **no** rights under Section 5. Specifically,
a Restricted Party is not licensed to download the Source Code outside GitHub's web
interface, to clone the repository, to obtain or install any Binary Release, or to
run the Software. The Author will not issue a Section 5.8 commercial license to a
Restricted Party.

**8.5 What is not withheld.** The Author does not purport to withhold, and this
Section does not withhold, (a) the GitHub Baseline Rights described in Section 4,
which arise from the platform's Terms of Service and which the Author cannot and
does not revoke; (b) any right conferred by law that a license cannot displace,
including fair use under 17 U.S.C. § 107; or (c) the right to read what is
publicly displayed. A Restricted Party may view and fork the repository on GitHub
like anyone else. What a Restricted Party may not do is take a copy outside the
platform, build it, run it, or make any Derivative Use of it.

**8.6 Reservation of remedies.** Nothing in this Section limits the Author's
remedies for conduct that occurred before its effective date, including remedies
under the AGPL v3 as it applied to earlier releases, under the DMCA, and under the
Lanham Act.

**8.7 Removal from the list.** A person identified in Section 8.3 who believes the
identification is mistaken, or who has ceased the conduct and remedied its effects
— by removing the derived material, correcting the attribution, and confirming
both in writing — may write to the Author at the address in Section 15. The Author
will consider any such statement in good faith and will amend this Section where
amendment is warranted. This Section is not a permanent bar and does not extend to
anyone who has not engaged in the conduct described in Section 8.2.

**8.8 Statements of fact.** The conduct described in this Section is stated as the
Author's account of events, supported by the Author's records. It is a factual
assertion offered in explanation of a licensing decision, made in good faith, and
subject to correction on presentation of contrary evidence.

---

## 9. ENFORCEMENT

**9.1 Copyright infringement.** A violation of Section 6 is copyright infringement
under 17 U.S.C. § 501. The Author is entitled to pursue:

(a) **injunctive relief** under 17 U.S.C. § 502, ordering immediate cessation of
the infringing activity;

(b) **impoundment and destruction** under § 503 of infringing copies and the means
of making them;

(c) **actual damages and profits of the infringer** under § 504(b), measured by the
Author's lost revenue and licensing fees and by any profit the infringer derived
from the infringement;

(d) **statutory damages** under § 504(c), where the infringed work was registered
before the infringement began or within three months of first publication, in the
amount of $750 to $30,000 per work infringed, or up to $150,000 per work where the
infringement was willful;

(e) **costs and attorney's fees** under § 505, where the infringed work was timely
registered.

The Author's ability to claim statutory damages and attorney's fees is contingent
on registration and is stated subject to that contingency.

**9.2 Digital Millennium Copyright Act.** Under 17 U.S.C. § 512(c), the Author may
and will issue takedown notices to any service provider hosting, indexing, or
facilitating access to an infringing copy, fork, derivative, or dataset containing
the Payload Data. That section conditions safe harbor on expeditious removal; a
provider that fails to remove material or that permits repeat infringers loses its
protection. Counter-notice under § 512(g) is available to anyone who believes a
takedown was issued in error.

**9.3 Anticircumvention.** Circumvention of a technical measure that effectively
controls access to the Software or that protects the Payload Data is prohibited by
17 U.S.C. § 1201(a) and (b) where those sections apply. Section 6.12 of this
License states the prohibition as a matter of contract; the statute imposes it as a
matter of law.

**9.4 Trademark and § 43(a).** The Author asserts common law trademark rights in
the name "SNIBypassGUI." Unauthorized use of that name on or in connection with a
Competing Project, including in the title or branding of a repository,
distribution, or release, is infringement under 15 U.S.C. § 1125(a)(1)(A). The
conduct described in Section 6.11 — attributing work to the Software or the Author
while directing the reader to another project — is false designation of origin
under § 1125(a)(1)(B), actionable as unfair competition. These claims are
independent of copyright.

**9.5 Computer Fraud and Abuse Act.** Where the Author employs technical measures
to control access to update services, distribution endpoints, or verification
infrastructure, circumvention of those measures, or access obtained by
impersonation, credential misuse, or exceeding granted authorization, may give rise
to liability under 18 U.S.C. § 1030. This Section makes no assertion as to where
that statute applies; its scope and reach are matters of federal law.

**9.6 Willfulness.** The conduct described in Section 6.15 — performing a
prohibited act and then omitting it from a public record, attributing it to
independent work, or publishing it only in an artifact while concealing it from a
source tree — is evidence that the infringement was willful within the meaning of
17 U.S.C. § 504(c)(2), and that enhanced statutory damages are warranted.
Publication of this License and of the Author's position as to the Payload Data's
protectability is notice to the world; conduct undertaken with knowledge of that
position and in disregard of it is by definition willful.

---

## 10. CHOICE OF LAW AND JURISDICTION

**10.1 Governing law.** This License, and any claim arising out of or relating to
the Software, is governed by:

(a) the copyright law of the United States, 17 U.S.C. § 101 *et seq.*;

(b) the Digital Millennium Copyright Act, 17 U.S.C. § 512 and §§ 1201–1205;

(c) the Lanham Act, 15 U.S.C. § 1125;

(d) where applicable, the Computer Fraud and Abuse Act, 18 U.S.C. § 1030; and

(e) the law of the State of California, without regard to its conflict-of-laws
principles, for claims sounding in contract, tort, or equity not otherwise governed
by federal statute.

**10.2 Jurisdiction — default.** Any action arising under this License may be
brought in the United States District Court for the Northern District of California
or in the Superior Court of California for the county in which the Author resides.
You consent to personal jurisdiction in those courts and waive any objection to
venue there.

**10.3 Alternative jurisdiction.** Where a Restricted Party identified in Section
8.3 or any other person whose principal place of residence or place of business is
within the territorial boundaries of the People's Republic of China (excluding Hong
Kong SAR, Macau SAR, and Taiwan) is the respondent or defendant, the Author
reserves the right to pursue remedies alternatively or concurrently under the laws
of the PRC and before PRC authorities, including:

(a) claims for copyright infringement under the Copyright Law of the People's
Republic of China (中华人民共和国著作权法);

(b) claims for unfair competition, commercial defamation, and misappropriation of
confidential business information under the Anti-Unfair Competition Law
(中华人民共和国反不正当竞争法);

(c) administrative complaints to the National Copyright Administration (国家版权局),
the State Administration for Market Regulation (国家市场监督管理总局), and platform
operators under applicable PRC notice-and-takedown procedures;

(d) where the scale and harm meet the statutory threshold, referral to prosecuting
authorities under Article 217 of the PRC Criminal Law (侵犯著作权罪).

The choice of jurisdiction is at the Author's sole election and does not constitute
a waiver of any right in any other forum. Pursuit in one forum does not bar
concurrent or subsequent pursuit in another.

**10.4 Rationale for U.S. law.** U.S. law governs because the Software is
distributed through GitHub, Inc., a U.S. company subject to U.S. law; because the
DMCA provides a notice-and-takedown mechanism suited to online distribution; and
because statutory damages under 17 U.S.C. § 504(c) do not require proof of actual
harm, making enforcement materially more effective.

---

## 11. DISCLAIMER OF WARRANTY

**11.1 AS IS.** THE SOFTWARE IS PROVIDED "AS IS" AND "AS AVAILABLE," WITHOUT
WARRANTY OF ANY KIND, EXPRESS OR IMPLIED. TO THE MAXIMUM EXTENT PERMITTED BY
APPLICABLE LAW, THE AUTHOR DISCLAIMS ALL WARRANTIES, INCLUDING THE IMPLIED
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE,
NON-INFRINGEMENT, ACCURACY, RELIABILITY, QUIET ENJOYMENT, AND ANY WARRANTY ARISING
FROM COURSE OF DEALING, USAGE, OR TRADE PRACTICE.

**11.2 No guarantee of results.** The Author does not warrant that the Software
will meet your requirements, will operate without interruption or error, or that
defects will be corrected. The Author does not warrant the accuracy, completeness,
reliability, currentness, or utility of the Payload Data or of any result obtained
through the Software.

**11.3 Third-party services.** The Software may enable access to content, services,
or resources operated by third parties. The Author makes no representation or
warranty regarding such third-party services, has no control over them, and accepts
no responsibility for their availability, content, or conduct. Any dealings you have
with third parties accessed through or in connection with the Software are solely
between you and them.

**11.4 Security.** No software is perfectly secure. The Author does not warrant that
the Software is free of vulnerabilities, that it will protect against all threats,
or that its use will not expose you to risk. You are solely responsible for
securing your system and for any consequence of a security incident.

**11.5 Basis of the bargain.** This Section is a fundamental part of the bargain
between you and the Author. The Author would not make the Software available without
it. Some jurisdictions do not permit exclusion of implied warranties, and to that
extent this Section may not fully apply to you; where it does not, the warranty
period is the minimum that jurisdiction permits, and any warranty extends only to
the person to whom the Author originally granted the license and may not be
transferred.

---

## 12. LIMITATION OF LIABILITY

**12.1 Exclusion of damages.** TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW,
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, PUNITIVE, RELIANCE, OR CONSEQUENTIAL DAMAGES, OR FOR LOSS OF
USE, LOSS OF DATA, LOSS OF REVENUE OR PROFIT, COST OF COVER, BUSINESS
INTERRUPTION, REPUTATIONAL HARM, OR ANY OTHER PECUNIARY OR NON-PECUNIARY LOSS,
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, TORT (INCLUDING NEGLIGENCE), BREACH OF WARRANTY, MISREPRESENTATION, OR
OTHERWISE, ARISING OUT OF OR IN ANY WAY RELATED TO THE SOFTWARE, ITS USE, OR THIS
LICENSE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

**12.2 Examples without limitation.** The exclusion in Section 12.1 applies to,
among other things:

(a) damage to equipment, systems, or data;

(b) suspension, termination, or banning of your account by any online service,
platform, game, streaming provider, or other third party;

(c) loss of access to content, subscriptions, virtual goods, account balances, or
purchased items as a result of such suspension or termination;

(d) detection, investigation, prosecution, conviction, fine, administrative
sanction, or any other legal or governmental consequence in any jurisdiction;

(e) denial of entry, visa revocation, travel restriction, deportation, detention,
or any other immigration or border-control consequence;

(f) employment termination, professional discipline, security clearance revocation,
or reputational harm;

(g) the acts, omissions, terms of service, policies, or enforcement decisions of
any third party;

(h) failure of the Software to bypass, evade, or circumvent any technical measure,
content filter, access control, geographic restriction, or network policy;

(i) any use of the Software contrary to the law of your jurisdiction or to the
terms of service of a third party.

**12.3 Cap.** If, notwithstanding Sections 11 and 12.1, the Author is found liable
to you for any reason, the Author's total aggregate liability shall not exceed the
amount you actually paid to the Author to acquire the Software, which in the case of
a free distribution is zero.

**12.4 Fundamental basis.** Like Section 11, this Section is a fundamental part of
the bargain. The Author would not make the Software available without it. Some
jurisdictions restrict limitations of liability for personal injury, gross
negligence, or willful misconduct; where such a restriction applies, it limits this
Section to that extent, and this Section otherwise remains in full force and effect.

**12.5 Your responsibility.** You are solely responsible for:

(a) determining whether use of the Software is lawful in your jurisdiction and
whether it complies with the terms of service of any third party whose service you
access;

(b) assessing and accepting the risks of use, including legal, technical, financial,
and reputational risks;

(c) configuring the Software appropriately and using it in a manner consistent with
applicable law and third-party terms;

(d) maintaining backups and taking such other precautions as a reasonable person
would take;

(e) any injury, loss, or consequence that results from your use of the Software or
from your decision to obtain it.

---

## 13. TERMINATION

**13.1 Automatic termination.** Your rights under Section 5 terminate automatically,
immediately, and without notice if you violate any term of this License. The GitHub
Baseline Rights are governed by GitHub's Terms of Service, not by this License, and
do not terminate under this Section.

**13.2 Effect of termination.** On termination you must immediately:

(a) cease all use of the Software, the Source Code, and the Payload Data;

(b) delete and destroy all copies in your possession or control, including installed
copies, downloaded archives, clones, and any derivative or extracted material; and

(c) if the Author requests it, certify in writing within seven days that you have
done so.

Termination does not relieve you of any liability incurred before termination,
including liability for infringement. The Author's remedies for your breach are
cumulative and are not waived by termination.

**13.3 Survival.** The following survive termination: Sections 1 (Preamble), 2
(Definitions), 3.7 (Redistributor Obligations), 6 (Restrictions), 7 (Ownership), 8
(Restricted Parties), 9 (Enforcement), 10 (Choice of Law), 11 (Disclaimer), 12
(Limitation of Liability), 13.2 and 13.3 (Effect of Termination and Survival), and
14 (General Provisions).

**13.4 No refund.** Termination does not entitle you to any refund, credit, or
other consideration. Where the Software was provided without charge, there is
nothing to refund.

**13.5 Reinstatement.** Termination is final. The Author is under no obligation to
reinstate your license. Any request for reinstatement is at the Author's sole
discretion.

---

## 14. GENERAL PROVISIONS

**14.1 Entire agreement.** This License is the complete agreement between you and
the Author regarding the Software and supersedes all prior or contemporaneous
understandings, agreements, representations, and communications, whether written or
oral. It may be amended only by a writing signed by the Author, or by the Author's
publication of a new version under Section 14.2. No term or condition stated in any
purchase order, receipt, acknowledgment, or other document you submit will modify or
add to this License.

**14.2 Updates to this License.** The Author reserves the right to publish an
updated version of this License at any time by committing it to the repository or by
distributing it with a Binary Release. The updated version applies to the copy you
obtained with it and to all subsequent copies, and it applies to your continued use
of any earlier copy. **Your continued use of the Software, in any version or from
any source, after the effective date of an updated License constitutes your
acceptance of the update.** The version and effective date appear at the top of this
document. You are responsible for reviewing the License periodically. If you do not
agree to an update, your sole remedy is to cease all use under Section 13.2.

**14.3 Severability.** If any provision of this License is held invalid,
unenforceable, or contrary to law by a court of competent jurisdiction, that
provision will be modified to the minimum extent necessary to make it valid and
enforceable, or if it cannot be made so, it will be severed, and the remainder of
the License will continue in full force and effect. The invalidity or
unenforceability of any provision in one jurisdiction does not affect its validity
or enforceability in another.

**14.4 No waiver.** The Author's failure to enforce any provision of this License,
or to exercise any right under it, is not a waiver of that provision or right and
does not prevent the Author from later enforcing it. A waiver is effective only if
made in writing and signed by the Author, and it applies only to the specific
instance addressed in the waiver.

**14.5 No agency.** This License does not create a partnership, joint venture,
agency, franchise, or employment relationship. You have no authority to bind the
Author or to make any representation on the Author's behalf.

**14.6 No assignment by you.** You may not assign, transfer, sublicense, or
delegate your rights or obligations under this License without the Author's prior
written consent. Any attempt to do so is void. This License binds and benefits the
parties and their permitted successors and assigns.

**14.7 Export compliance.** The Software may be subject to export control laws and
regulations, including the Export Administration Regulations of the United States.
You represent that you are not located in, under the control of, or a national or
resident of any country to which export is prohibited, and that you are not on any
U.S. government list of prohibited or restricted parties. You will comply with all
applicable export and re-export restrictions.

**14.8 U.S. Government users.** The Software is "commercial computer software" and
"commercial computer software documentation" as those terms are used in 48 C.F.R.
§ 2.101. If acquired by or on behalf of a civilian agency, it is subject to the
rights and restrictions of this License per 48 C.F.R. § 12.212. If acquired by or
on behalf of the Department of Defense, it is subject to the rights and
restrictions of this License per 48 C.F.R. § 227.7202. Use, duplication, or
disclosure by the Government is subject to the restrictions in this License.

**14.9 Interpretation.** Headings are for convenience only and do not limit or
affect the meaning of any provision. "Including" means "including without
limitation." "Or" is inclusive unless the context requires otherwise. The singular
includes the plural and the plural includes the singular. This License will not be
construed against the Author as drafter.

**14.10 Language.** This License is written and executed in English. Any translation
is provided for convenience only, and in the event of conflict, the English text
controls.

**14.11 Notice.** Any notice to the Author under this License must be in writing and
sent to the address in Section 15. Email to that address is sufficient. The Author
may give notice to you by posting to the repository, by including a notice in a
Binary Release or update package, or by email to any address you have provided.
Notice is deemed given when sent.

---

## 15. CONTACT AND NOTICES

For licensing inquiries, commercial licensing requests, security disclosures, and
enforcement matters:

- **Email:** snibypassgui@gmail.com or racpast@gmail.com  
- **GitHub Issues:** Issues may be opened on this repository for technical matters.
  Licensing and enforcement inquiries should be directed to email.

Security disclosures may also be submitted through GitHub's private vulnerability
reporting mechanism where available.

---

**END OF LICENSE**

**© 2026 Racpast. All rights reserved.**
