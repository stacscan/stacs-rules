[![Shield](https://img.shields.io/github/workflow/status/stacscan/stacs-rules/Check?label=Tests&style=flat-square)](https://github.com/stacscan/stacs-rules/actions?workflow=Check)
[![Shield](https://img.shields.io/twitter/follow/stacscan?style=flat-square)](https://twitter.com/stacscan)
<p align="center">
    <br /><br />
    <img src="./docs/images/STACS-Logo-RGB.small.png?raw=true">
</p>
<p align="center">
    <br />
    <b>Static Token And Credential Scanner Community Rules.</b>
    <br />
</p>

### What is it?

This repository contains community rule packs for use with STACS. Please see the
[STACS](https://www.github.com/stacscan/stacs) repository for more information!

### Testing

In order to ensure that new rules are tested appropriately, a set of negative and
positive test fixtures should exist for all rules. These must live under the `tests`
directory and reflect the same structure as the rule itself - including the rule name.

As an example, the following shell snippet will generate `negative` and `positive`
directories for all rules of a defined `RULE_TYPE` when run from the root of this
repository.

```shell
find rules -name *.yar | sed 's/rules\///' \
    | xargs -I{} sh -c "\
        mkdir -p ./tests/fixtures/{}/{positive,negative} ; \
        touch ./tests/fixtures/{}/{negative,positive}/.gitignore"
```

These directories must then be populated with fixtures which demonstrate both a positive
match (`positive`) and a negative match (`negative`). Ideally, negative tests should be
close to a match, but not exact - rather than just a random block of data. This is in
order to ensure that partial matches do not trigger a finding.
