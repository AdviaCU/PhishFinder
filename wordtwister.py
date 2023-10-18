from collections import OrderedDict
# ===========================================================
# Author: Oto R.
# Credits: https://github.com/elceef/dnstwist
# Date: September 2023
# Version: 1.0
# Description: PhishFinder - Find high risk domains
# Organization: Advia Credit Union, Information Security Department
# ===========================================================
class Fuzzer():
	glyphs_unicode = {
		'2': ('ƻ',),
		'3': ('ʒ',),
		'5': ('ƽ',),
		'a': ('ạ', 'ă', 'ȧ', 'ɑ', 'å', 'ą', 'â', 'ǎ', 'á', 'ə', 'ä', 'ã', 'ā', 'à'),
		'b': ('ḃ', 'ḅ', 'ƅ', 'ʙ', 'ḇ', 'ɓ'),
		'c': ('č', 'ᴄ', 'ċ', 'ç', 'ć', 'ĉ', 'ƈ'),
		'd': ('ď', 'ḍ', 'ḋ', 'ɖ', 'ḏ', 'ɗ', 'ḓ', 'ḑ', 'đ'),
		'e': ('ê', 'ẹ', 'ę', 'è', 'ḛ', 'ě', 'ɇ', 'ė', 'ĕ', 'é', 'ë', 'ē', 'ȩ'),
		'f': ('ḟ', 'ƒ'),
		'g': ('ǧ', 'ġ', 'ǵ', 'ğ', 'ɡ', 'ǥ', 'ĝ', 'ģ', 'ɢ'),
		'h': ('ȟ', 'ḫ', 'ḩ', 'ḣ', 'ɦ', 'ḥ', 'ḧ', 'ħ', 'ẖ', 'ⱨ', 'ĥ'),
		'i': ('ɩ', 'ǐ', 'í', 'ɪ', 'ỉ', 'ȋ', 'ɨ', 'ï', 'ī', 'ĩ', 'ị', 'î', 'ı', 'ĭ', 'į', 'ì'),
		'j': ('ǰ', 'ĵ', 'ʝ', 'ɉ'),
		'k': ('ĸ', 'ǩ', 'ⱪ', 'ḵ', 'ķ', 'ᴋ', 'ḳ'),
		'l': ('ĺ', 'ł', 'ɫ', 'ļ', 'ľ'),
		'm': ('ᴍ', 'ṁ', 'ḿ', 'ṃ', 'ɱ'),
		'n': ('ņ', 'ǹ', 'ń', 'ň', 'ṅ', 'ṉ', 'ṇ', 'ꞑ', 'ñ', 'ŋ'),
		'o': ('ö', 'ó', 'ȯ', 'ỏ', 'ô', 'ᴏ', 'ō', 'ò', 'ŏ', 'ơ', 'ő', 'õ', 'ọ', 'ø'),
		'p': ('ṗ', 'ƿ', 'ƥ', 'ṕ'),
		'q': ('ʠ',),
		'r': ('ʀ', 'ȓ', 'ɍ', 'ɾ', 'ř', 'ṛ', 'ɽ', 'ȑ', 'ṙ', 'ŗ', 'ŕ', 'ɼ', 'ṟ'),
		's': ('ṡ', 'ș', 'ŝ', 'ꜱ', 'ʂ', 'š', 'ś', 'ṣ', 'ş'),
		't': ('ť', 'ƫ', 'ţ', 'ṭ', 'ṫ', 'ț', 'ŧ'),
		'u': ('ᴜ', 'ų', 'ŭ', 'ū', 'ű', 'ǔ', 'ȕ', 'ư', 'ù', 'ů', 'ʉ', 'ú', 'ȗ', 'ü', 'û', 'ũ', 'ụ'),
		'v': ('ᶌ', 'ṿ', 'ᴠ', 'ⱴ', 'ⱱ', 'ṽ'),
		'w': ('ᴡ', 'ẇ', 'ẅ', 'ẃ', 'ẘ', 'ẉ', 'ⱳ', 'ŵ', 'ẁ'),
		'x': ('ẋ', 'ẍ'),
		'y': ('ŷ', 'ÿ', 'ʏ', 'ẏ', 'ɏ', 'ƴ', 'ȳ', 'ý', 'ỿ', 'ỵ'),
		'z': ('ž', 'ƶ', 'ẓ', 'ẕ', 'ⱬ', 'ᴢ', 'ż', 'ź', 'ʐ'),
		'ae': ('æ',),
		'oe': ('œ',),
	}
	glyphs_ascii = {
		'0': ('o',),
		'1': ('l', 'i'),
		'3': ('8',),
		'6': ('9',),
		'8': ('3',),
		'9': ('6',),
		'b': ('d', 'lb'),
		'c': ('e',),
		'd': ('b', 'cl', 'dl'),
		'e': ('c',),
		'g': ('q',),
		'h': ('lh'),
		'i': ('1', 'l'),
		'k': ('lc'),
		'l': ('1', 'i'),
		'm': ('n', 'nn', 'rn', 'rr'),
		'n': ('m', 'r'),
		'o': ('0',),
		'q': ('g',),
		'w': ('vv',),
	}
	latin_to_cyrillic = {
		'a': 'а', 'b': 'ь', 'c': 'с', 'd': 'ԁ', 'e': 'е', 'g': 'ԍ', 'h': 'һ',
		'i': 'і', 'j': 'ј', 'k': 'к', 'l': 'ӏ', 'm': 'м', 'o': 'о', 'p': 'р',
		'q': 'ԛ', 's': 'ѕ', 't': 'т', 'v': 'ѵ', 'w': 'ԝ', 'x': 'х', 'y': 'у',
	}
	qwerty = {
		'1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
		'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
		'a': 'qwsz', 's': 'edxzaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
		'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
	}
	qwertz = {
		'1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7zt5', '7': '8uz6', '8': '9iu7', '9': '0oi8', '0': 'po9',
		'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6zgfr5', 'z': '7uhgt6', 'u': '8ijhz7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
		'a': 'qwsy', 's': 'edxyaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'zhbvft', 'h': 'ujnbgz', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
		'y': 'asx', 'x': 'ysdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
	}
	azerty = {
		'1': '2a', '2': '3za1', '3': '4ez2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
		'a': '2zq1', 'z': '3esqa2', 'e': '4rdsz3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0m',
		'q': 'zswa', 's': 'edxwqz', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'iknhu', 'k': 'olji', 'l': 'kopm', 'm': 'lp',
		'w': 'sxq', 'x': 'wsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhj'
	}
	keyboards = [qwerty, qwertz, azerty]

	def __init__(self, word):
		self.domain = word
	def _generate(self):
		dictionary = {
			'bitsquatting': self._bitsquatting(),
			'hyphenation': self._hyphenation(),
			'insertion': self._insertion(),
			'omission': self._omission(),
			'repetition': self._repetition(),
			'replacement': self._replacement(),
			'transposition': self._transposition(),
			'vowel_swap': self._vowel_swap(),
			'addition': self._addition(),
			'cyrillic': self._cyrillic(),
		}
		return dictionary
	
	def _bitsquatting(self):
		masks = [1, 2, 4, 8, 16, 32, 64, 128]
		chars = set('abcdefghijklmnopqrstuvwxyz0123456789-')
		for i, c in enumerate(self.domain):
			for mask in masks:
				b = chr(ord(c) ^ mask)
				if b in chars:
					return self.domain[:i] + b + self.domain[i+1:]

	def _cyrillic(self):
		cdomain = self.domain
		for l, c in self.latin_to_cyrillic.items():
			cdomain = cdomain.replace(l, c)
		for c, l in zip(cdomain, self.domain):
			if c == l:
				return []
		return [cdomain]

	def _homoglyph(self):
		md = lambda a, b: {k: set(a.get(k, [])) | set(b.get(k, [])) for k in set(a.keys()) | set(b.keys())}
		glyphs = md(self.glyphs_ascii, self.glyphs_idn_by_tld.get(self.tld, self.glyphs_unicode))
		def mix(domain):
			for i, c in enumerate(domain):
				for g in glyphs.get(c, []):
					yield domain[:i] + g + domain[i+1:]
			for i in range(len(domain)-1):
				win = domain[i:i+2]
				for c in {win[0], win[1], win}:
					for g in glyphs.get(c, []):
						yield domain[:i] + win.replace(c, g) + domain[i+2:]
		result1 = set(mix(self.domain))
		result2 = set()
		for r in result1:
			result2.update(set(mix(r)))
		return result1 | result2

	def _hyphenation(self):
		return {self.domain[:i] + '-' + self.domain[i:] for i in range(1, len(self.domain))}

	def _insertion(self):
		result = set()
		for i in range(1, len(self.domain)-1):
			prefix, orig_c, suffix = self.domain[:i], self.domain[i], self.domain[i+1:]
			for c in (c for keys in self.keyboards for c in keys.get(orig_c, [])):
				result.update({
					prefix + c + orig_c + suffix,
					prefix + orig_c + c + suffix
				})
		return result

	def _omission(self):
		return {self.domain[:i] + self.domain[i+1:] for i in range(len(self.domain))}

	def _repetition(self):
		return {self.domain[:i] + c + self.domain[i:] for i, c in enumerate(self.domain)}

	def _replacement(self):
		for i, c in enumerate(self.domain):
			pre = self.domain[:i]
			suf = self.domain[i+1:]
			for layout in self.keyboards:
				for r in layout.get(c, ''):
					return pre + r + suf

	def _transposition(self):
		return {self.domain[:i] + self.domain[i+1] + self.domain[i] + self.domain[i+2:] for i in range(len(self.domain)-1)}

	def _vowel_swap(self):
		vowels = 'aeiou'
		for i in range(0, len(self.domain)):
			for vowel in vowels:
				if self.domain[i] in vowels:
					return self.domain[:i] + vowel + self.domain[i+1:]

	def _addition(self):
		return {self.domain + chr(i) for i in (*range(48, 58), *range(97, 123))}

	def _dictionary(self):
		result = set()
		for word in self.dictionary:
			if not (self.domain.startswith(word) and self.domain.endswith(word)):
				result.update({
					self.domain + '-' + word,
					self.domain + word,
					word + '-' + self.domain,
					word + self.domain
				})
		if '-' in self.domain:
			parts = self.domain.split('-')
			for word in self.dictionary:
				result.update({
					'-'.join(parts[:-1]) + '-' + word,
					word + '-' + '-'.join(parts[1:])
				})
		return result

if __name__ == '__main__':
	watchlist = []
	with open("feedlist.txt", "r") as f:
		lines = f.readlines()
		#pprint(lines)
		for line in lines:
			line = line.strip()
			watchlist.append(line)
			if len(line) > 4:
				#print(line)
				fuzz = Fuzzer(line)._generate()
				for key, value in fuzz.items():
					if type(value) is str:
						watchlist.append(value)
					else:
						for v in value:
							watchlist.append(v)
	
	watchlist = list(OrderedDict.fromkeys(watchlist))
	watchlist.sort()
	with open("watchlist.txt", "w") as f:
		for line in watchlist:
			if line != "":
				f.write(line + "\n")