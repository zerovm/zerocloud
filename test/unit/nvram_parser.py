from ConfigParser import ConfigParser, MissingSectionHeaderError, ParsingError
import sys
import re

__version__ = "1.0"

try:
    from collections import OrderedDict as _default_dict
except ImportError:
    # fallback for setup.py which hasn't yet built _collections
    _default_dict = dict

DEFAULTSECT = "DEFAULT"


class NvramParser(ConfigParser):
    def __init__(self, defaults=None, dict_type=_default_dict,
                 allow_no_value=False):
        ConfigParser.__init__(self, defaults=defaults,
                              dict_type=dict_type,
                              allow_no_value=allow_no_value)
        self._envcre = re.compile(
            r'name\s*(?P<vi>[=])\s*(?P<option>[^,]*),\s*'
            r'value\s*=\s*(?P<value>.*)$'
        )
        self._envvre = re.compile(r'\\x2c')

    def _read(self, fp, fpname):
        """Parse a sectioned setup file.

        The sections in setup file contains a title line at the top,
        indicated by a name in square brackets (`[]'), plus key/value
        options lines, indicated by `name: value' format lines.
        Continuations are represented by an embedded newline then
        leading whitespace.  Blank lines, lines beginning with a '#',
        and just about everything else are ignored.
        """
        cursect = None                        # None, or a dictionary
        optname = None
        lineno = 0
        e = None                              # None, or an exception
        while True:
            line = fp.readline()
            if not line:
                break
            lineno += 1
            # comment or blank line?
            if line.strip() == '' or line[0] in '#;':
                continue
            if line.split(None, 1)[0].lower() == 'rem' and line[0] in "rR":
                # no leading whitespace
                continue
                # continuation line?
            if line[0].isspace() and cursect is not None and optname:
                value = line.strip()
                if value:
                    cursect[optname].append(value)
            # a section header or option header?
            else:
                # is it a section header?
                mo = self.SECTCRE.match(line)
                if mo:
                    sectname = mo.group('header')
                    if sectname in self._sections:
                        cursect = self._sections[sectname]
                    elif sectname == DEFAULTSECT:
                        cursect = self._defaults
                    else:
                        cursect = self._dict()
                        cursect['__name__'] = sectname
                        self._sections[sectname] = cursect
                        # So sections can't start with a continuation line
                    optname = None
                # no section header in the file?
                elif cursect is None:
                    raise MissingSectionHeaderError(fpname, lineno, line)
                # an option line?
                else:
                    if 'env' in cursect['__name__']:
                        mo = self._envcre.match(line)
                    else:
                        mo = self._optcre.match(line)
                    if mo:
                        optname, vi, optval = mo.group('option', 'vi', 'value')
                        optname = self.optionxform(optname.rstrip())
                        # This check is fine because the OPTCRE cannot
                        # match if it would set optval to None
                        if optval is not None:
                            optval = self._envvre.sub(',', optval).strip()
                            # allow empty values
                            if optval == '""':
                                optval = ''
                            cursect[optname] = [optval]
                        else:
                            # valueless option handling
                            cursect[optname] = optval
                    else:
                        # a non-fatal parsing error occurred.  set up the
                        # exception but keep going. the exception will be
                        # raised at the end of the file and will contain a
                        # list of all bogus lines
                        if not e:
                            e = ParsingError(fpname)
                        e.append(lineno, repr(line))
                        # if any parsing errors occurred, raise an exception
        if e:
            raise e

        # join the multi-line values collected while reading
        all_sections = [self._defaults]
        all_sections.extend(self._sections.values())
        for options in all_sections:
            for name, val in options.items():
                if isinstance(val, list):
                    options[name] = '\n'.join(val)


def readconf(conffile, section_name=None, defaults=None):
    """
    Read config file and return config items as a dict

    :param conffile: path to config file, or a file-like object (hasattr
                     readline)
    :param section_name: config section to read (will return all sections if
                     not defined)
    :param defaults: dict of default values to pre-populate the config with
    :returns: dict of config items
    """
    if defaults is None:
        defaults = {}
    c = NvramParser(defaults)
    c.optionxform = str

    if hasattr(conffile, 'readline'):
        c.readfp(conffile)
    else:
        if not c.read(conffile):
            print "Unable to read config file %s" % conffile
            sys.exit(1)
    if section_name:
        if c.has_section(section_name):
            conf = dict(c.items(section_name))
        else:
            return {}
    else:
        conf = {}
        for s in c.sections():
            conf.update({s: dict(c.items(s))})
    return conf


def read_env(nvram_file):
    return readconf(nvram_file, section_name='env')

if __name__ == '__main__':
    import json
    print json.dumps(read_env(sys.argv[1]), indent=2)
