# -*- coding: utf-8 -*-
# © Toons

import hashlib
import unittest

from ecpy.curves import Curve, Point
from ecpy.keys import ECPrivateKey, ECPublicKey
from ecpy.ecschnorr import ECSchnorr


class TestEcschnorr(unittest.TestCase):

	types = ["ISO","ISOx","BSI","Z"]

	@classmethod
	def setUpClass(self):
		self.secp256k1 = Curve.get_curve('secp256k1')
		self.privK = ECPrivateKey(
			0xfb26a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5,
			self.secp256k1)
		self.pubK = self.privK.get_public_key()
		self.msg = "shnorr signature test message".encode("utf-8")
		for typ in TestEcschnorr.types:
			setattr(self, typ.lower(), ECSchnorr(hashlib.sha256, typ))
	
	def test_sign_ecrand(self):
		for typ in TestEcschnorr.types:
			signer = getattr(self, typ.lower())
			msg = signer._hasher(self.msg).digest()
			self.assertEqual(True, signer.verify(msg, signer.sign(msg, self.privK), self.pubK))

	def test_sign_rfc6979(self):
		for typ in TestEcschnorr.types:
			signer = getattr(self, typ.lower())
			msg = signer._hasher(self.msg).digest()
			self.assertEqual(True, signer.verify(msg, signer.sign_rfc6979(msg, self.privK), self.pubK))

	def test_sign_bip(self):
		signer = ECSchnorr(hashlib.sha256, "BIP", fmt="RAW")
		msg = signer._hasher(self.msg).digest()
		self.assertEqual(True, signer.bip_verify(msg, signer.bip_sign(msg, self.privK), self.pubK))

