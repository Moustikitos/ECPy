`ecpy.curves`
=============

::

    >>> from ecpy.curves import Curve, Point
    >>> P = Point(
    ...    0x65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b21,
    ...    None,
    ...    curve=Curve.get_curve('secp256k1')
    ...)
    >>> print(P)
        x: 65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b21
        y: c60f7f83182063ff2a2666123de8a079c4bf43cf5d3c7d624858f20e818fb70f
        point on 'secp256k1' curve
    >>> k = 0xfb26a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5
    >>> Q = k * P
    >>> R = P + Q
    >>> print(R)
        x: 1f660f74ade02f05292a3b4f224e2a90a66a239842c34f3669350cd74a1701aa
        y: ab23496cb4231fb70ef61b990a0e84bc4d2c4bb9a2c8ea9c4ba4c32bd3cbeb2f
        point on 'secp256k1' curve

.. automodule:: ecpy.curves
   :members:
