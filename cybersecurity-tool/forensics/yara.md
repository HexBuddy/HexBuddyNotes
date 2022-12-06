# YARA

### Introduction

I like YARA. Every time I hear its name spoken aloud it makes me chuckle and think I should start gabbing in German. Even though its origins are somewhat more south and on a different continent, specifically South America for the curious. It never ceases to amaze me how many sharp people in our industry have not used it or, in some cases, not even heard of it. YARA is a tool aimed at (but not limited to) helping malware researchers identify and classify malware samples. It has been around for a bit and has an active, growing community that supports it. As an open source project written in raw C and [provided freely via Github](http://virustotal.github.io/yara/), it’s tough to beat its price.

### What does it do?

Well, that’s easy to describe. YARA contains a smorgasbord of pattern matching capabilities. It can be a sniper, zoning in one a single target or a legion of soldiers linking shields and moving across a battlefield. Both are accurate depictions of its ability to detect, either through extreme accuracy or broad strokes. We used to joke that YARA ate artillery shells and drank napalm, a testament to how powerful it was when it came to finding things. It’s also as smart as you make it; with the logic coming from the user.

YARA is not just for binaries.

### More YARA love

You might be wondering still, what it is. On one hand, YARA is a lightweight, flexible tool, usable across just about any operating system. With its source code available, it’s easy to tailor or extend to make it fit a specific use case. YARA is an easy one to fit it into a trusted toolset for digital forensics, incident response or reverse engineering. On the other hand, YARA is your bloodhound. It lives to find, to detect and puzzle out twists and turns of logic. Its targets are files, the ones you commonly think of - binaries, documents, drivers, and so on. It also scans the ones you might not think of, like network traffic, data stores, and so on. It’s been quietly woven into the fabric of a lot of tools and you might be surprised that your SIEM, triage tool, phishing, sandbox or IDS [can employ it](http://virustotal.github.io/yara/). It’s usually something you find out after the fact when you learn of YARA’s existence.

YARA runs from a command line on both Linux and Windows, which is handy when you are working locally for reverse engineering or incident response. You can bring it online fast by opening it up in terminal and just as easily put it to work by handing it logic and a target. Graphically, it wins no awards and frankly makes no attempts to change that. Its better served by leveraging the numerous Python, Ruby, Go and other bindings to it that plug it into something graphical or wrap it in an API.

The logic that forms YARA’s brain is the just as streamlined and simple. YARA takes input at the terminal or you can provide it a simple text file of logic. It thinks in patterns that you fashion from rules and its Ying/Yang is pure true or false. The rules are sleek. You provide the name, the elements to match and pattern to match on. You can create the rule from a target, by sleuthing its insides and building matches, or do the opposite; derive a pattern and find targets that correspond to the logic.

There was a related blog on YARA support in OTX last week.

### Writing YARA Rules

At its simplest, the elements to match can be something readable in ASCII, Unicode, or Hex. Declarative assignment is easy, it’s either there or it’s not, and the presence or lack of the element in a target takes on meaning to the logical pattern. It also speaks regex, and very intricate patterns can be built as elements to incorporate as the logic. This level of declarative discovery via YARA may be all you need, whether it’s to craft simple ASCII text, interesting Hex strings or intricate regex. I’ve pulled out a nice sample to show what it looks like in a rule using some of these elements. In case, this rule is aimed at any kind of file – it frankly doesn’t care what the target is, be it binary, html, image or other formats. The logic in it looks at a couple of simple shellcode possibilities and would be used in chain with other rules in a rule set.

```
rule Poss_Shell_Patterns_1

{

strings:

$reg1 = /=s*?unescape(s*?
?s*["'](%u[a-fA-F0-9]{4}|%[a-fA-F0-9]{2}){2,}['"]s*?[+)]/

$reg2 = /document.write(unescape(s*?
?s*["'](%u[a-fA-F0-9]{4}|%[a-fA-F0-9]{2}){2,}['"]/

condition:

$reg1 or reg2

}
```

As you might infer from the text above, the structure of the rule is straightforward. Don’t let that simplicity fool you. While we showed an example of declarative matching, i.e., it’s present or not, YARA is by no means locked only into that model.

Two other useful techniques are detection by proximity or by container. Proximity is exactly what it sounds, where the logic revolves around defining an element and then interrogating to find out if matching elements exist congruently around it. An example would be defining a hex string of $hex = { 25 45 66 3F 2E } and then looking for where the two elements around it in steps of 5, 10 or 15 bytes. For example:

for in in (0..#hex): (@hex\[i]+5 == “cyber” or @hex\[i]+10 == “defenses” or @hex\[i]+15 == “Alienvault”).

The logic above, like the previous rule, could care less about its target – it can be anything. The rule only cares about finding matches to the logic expressed, in this case in an iterative fashion starting with the first match to the hex string and end with the last.

Containers are exactly what they sound like, where an element is contained within a bounding box you describe. Here, we might look for our previously defined $hex string but only within a custom defined location, like between it and another element, say $string\_start and $string\_finish. The logic would be $hex in (@string\_start..@string\_finish). Or, not in that range, such as $hex not in (@string\_start..string\_@finish).

![](https://cdn-cybersecurity.att.com/blog-content/Yara\_blog.png)

_Figure 1 YARA Bounding Box example_

Some other useful techniques are counting, location, and procession, or the order of elements appearing. Counting is what is sounds like and leverages the count of some element as part of its logic and it can be equal, not equal, greater than, less than, etc. Location is using where the element appears in the file as a means of detection. It’s like the previously mentioned proximity and containment techniques, except it aligns to the file instead of a custom container. Procession is the order of the elements, and the elements searched might be text, let’s say, such as:

$a = “cyberdefenses” and $b = “SIEM” and $c = “Alienvault”

The appearance is mathematical, as in asking for a pattern of where $a < $b < $c or any other combination, such as $b < $a > $c and so forth.

### YARA Modules

There are plenty of other techniques to discuss but I hope these give you some insight into how applicable its logic can be against more complex puzzles. YARA is very extensible, as well, and its supportive community has expanded its capability with modules. One very commonly used module is the portable executable or [PE module](https://yara.readthedocs.io/en/v3.6.3/modules/pe.html). It eases logic by providing more predefined elements for PE files and simplifies logic calls by handling some processes automatically. The [Math module](https://yara.readthedocs.io/en/v3.6.3/modules/math.html) is another and it opens up a ton of functions that are handy. Plenty more exist, and you can find them [here](https://yara.readthedocs.io/en/v3.6.3/modules.html). They tend to provide new functions that can be leveraged or ease the burden with predefined attributes to ease detection.

### Sets of YARA Rules

While we tend to focus on the rules individually, they are meant to be used in sets and a rule set might contain, 1, 10 or 1000 or even more rules strung along in a sequence. It’s when you understand the concept of leveraging sets that you truly start harnessing YARA’s power. Rules are read from top to bottom in a rule set. Each will resolve completely before moving to the next so you can incorporate the results of an earlier rule into one that follows. Not just singly, but in any number. Any number of resolved rules can be repurposed into the conditional logic of a rule that follows. In fact, below is an example of where a rule was written to discover portable executable (PE) files with a specific import hash value, a specific section containing the entry point and then specific strings. Note, the use of “import pe”, which tells YARA that we are using the PE module and how the second rule “drops” the strings section and only uses logic to define a condition.

import "pe"

rule interesting\_strings\_1

{

strings:

$ = { 98 05 00 00 06 }

$ = "360saf" nocase

$ = "linkbl.gif"

$ = "mailadword"

condition:

any of them

}

rule par\_import

{

condition:

interesting\_strings\_1 and pe.imphash() == "87421be9519ab6eb9bdd8d2f318ff35f"

}

rule Poss\_polymorphic\_malware

{

condition:

par\_import and (pe.sections\[pe.section\_index(pe.entry\_point)].name contains "" or pe.sections\[pe.section\_index(pe.entry\_point)].name contains "p")

}

As I’m hinting, rule sets mean you can re-use logic and follow the principle of “write once, use often”. They also mean you can form a chain of inheritance, where rules can inherit the results of another and apply that in their logic. It also means modular construction, especially since YARA supports importing, so you can abstract your logic into multiple rulesets and import them in on an as needed basis. When it comes to juggling large volumes of rules in rule sets, that becomes an invaluable management and Quality assurance tool.

### Why use YARA?

YARA seems simple, and it is, but YARA is very versatile in application. I could expound all day on its capability but its seems unfair to do so without touching on how its employed.

Perhaps the simplest use case to describe is its play in the reverse engineering world. If you Reverse Engineer malware and don’t leverage it, you are missing out on a fast win to speed your process. To match a file by its attributes, to classify groups of files into families, identify algorithms, find code caves, code stomping, and more are all easy applications.

Incident response? No problem. At some point, you start parsing files to understand how they align to the event that spawned the response. That’s when YARA comes into play, either to play a role like it would with malware that might be present or to fast search and find elements of interest.

If you gather file intelligence of any kind or maintain a lab that interrogates files of interest, then YARA can be a chief workhorse in the process. It can detect and identify by any attribute of a file, including those left by the compiler, the composer or cracker. With the right logic, like we previously discussed, the structure, as well as the containment and order of elements in a file become valid bundles of intelligence to be harvested.

The previous examples are pretty standalone instances but YARA also shines as a support and follow on tool, as well. Do you send files to a sandbox? If so, it can enrich the outcome and understanding gained from detonating the file in the sandbox. The same applies if you use it in your email filter, to triage phishing, in your SIEM, which, speaking of, Alienvault supports.

### Conclusion

In short, YARA is versatile, powerful and available. Its learning curve is gentle and its application is broad. In a world where your foe hides in plain sight and around the corner, it has insane detection capability to cast a light on the suspicious, malicious or _plain just interesting_. If it hasn’t found a home in your toolkit, it’s time to step up and make it happen. If you need a hand in exploring its capability, [we can show you how](https://www.cyberdefenses.com/?=YARA). Lastly, you should always demand the best.
