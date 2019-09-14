# -*- coding: utf-8 -*-
# © Toons

import unittest
import binascii

from ecpy import encoders
from ecpy import formatters
from ecpy.curves import Curve, Point


class TestEncoders(unittest.TestCase):

	@classmethod
	def setUpClass(self):
		self.secp256k1 = Curve.get_curve('secp256k1')
		self.r = 0x24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c
		self.s = 0xacd417b277ab7e7d993cc4a601dd01a71696fd0dd2e93561d9de9b69dd4dc75c
		self.P1 = Point(
			0x6fb13b7e8ab1c7d191d16197c1bf7f8dc7992412e1266155b3fb3ac8b30f3ed8,
			0x2e1eb77bd89505113819600b395e0475d102c4788a3280a583d9d82625ed8533,
			self.secp256k1,
			check=True)

		self.ed25519 = Curve.get_curve('Ed25519')
		self.P2 = Point(
			0x67ae9c4a22928f491ff4ae743edac83a6343981981624886ac62485fd3f8e25c,
			0x1267b1d177ee69aba126a18e60269ef79f16ec176724030402c3684878f5b4d4,
			self.ed25519,
			check=True)

		self.curve25519 = Curve.get_curve('Curve25519')


	def test_scalar_25519_encoder(self):
		k = binascii.unhexlify("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
		self.assertEqual(
			encoders.decode_scalar_25519(k),
			31029842492115040904895560451863089656472772604678260265531221036453811406496)

	def test_secp256k1_encoder(self):
		x, y = self.P1.x, self.P1.y
		encoder = encoders.Secp256k1(self.secp256k1, compressed=False)
		self.assertEqual((x, y), encoder.decode(encoder.encode(x, y), self.secp256k1))
		encoder = encoders.Secp256k1(self.secp256k1, compressed=True)
		self.assertEqual((x, y), encoder.decode(encoder.encode(x, y), self.secp256k1))

	def test_p1363_2000_encoder(self):
		x, y = self.P1.x, self.P1.y
		encoder = encoders.P1363_2000(self.secp256k1, compressed=False)
		self.assertEqual((x, y), encoder.decode(encoder.encode(x, y), self.secp256k1))
		encoder = encoders.P1363_2000(self.secp256k1, compressed=True)
		self.assertEqual((x, y), encoder.decode(encoder.encode(x, y), self.secp256k1))

	def test_rfc87748_encoder(self):
		x, y = 34426434033919594451155107781188821651316167215306631574996226621102155684838, None
		encoder = encoders.Rfc87748(self.curve25519, compressed=False)
		self.assertEqual((x, y), encoder.decode(encoder.encode(x, y), self.curve25519))
		encoder = encoders.Rfc87748(self.curve25519, compressed=True)
		self.assertEqual((x, y), encoder.decode(encoder.encode(x, y), self.curve25519))

	def test_eddsa04_encoder(self):
		x, y = self.P2.x, self.P2.y
		encoder = encoders.Eddsa04(self.ed25519, compressed=False)
		self.assertEqual((x, y), encoder.decode(encoder.encode(x, y), self.ed25519))
		encoder = encoders.Eddsa04(self.ed25519, compressed=True)
		self.assertEqual((x, y), encoder.decode(encoder.encode(x, y), self.ed25519))

	def test_der_signature_encoder(self):
		r, s = self.r, self.s
		self.assertEqual((r, s), formatters.decode_sig(formatters.encode_sig(r, s, fmt="DER"), fmt="DER"))

	def test_btuple_signature_encoder(self):
		r, s = self.r, self.s
		self.assertEqual((r, s), formatters.decode_sig(formatters.encode_sig(r, s, fmt="BTUPLE"), fmt="BTUPLE"))

	def test_ituple_signature_encoder(self):
		r, s = self.r, self.s
		self.assertEqual((r, s), formatters.decode_sig(formatters.encode_sig(r, s, fmt="ITUPLE"), fmt="ITUPLE"))

	def test_raw_signature_encoder(self):
		r, s = self.r, self.s
		self.assertEqual((r, s), formatters.decode_sig(formatters.encode_sig(r, s, fmt="RAW"), fmt="RAW"))

	def test_eddsa_signature_encoder(self):
		r, s = self.r, self.s
		self.assertEqual((r, s), formatters.decode_sig(formatters.encode_sig(r, s, fmt="EDDSA"), fmt="EDDSA"))
