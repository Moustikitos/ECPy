`ecpy.curves`
=============

::

    >>> from ecpy.curves import Curve, Point
    >>> cv = Curve.get_curve('secp256k1')
    >>> P = Point(
    ...    0x65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b21,
    ...    curve=cv
    ...)
    >>> print(P)
    <Point
        x: 65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b21
        y: 39f0807ce7df9c00d5d999edc2175f863b40bc30a2c3829db7a70df07e704520
        point on 'secp256k1' curve>
    >>> k = 0xfb26a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5
    >>> Q = k * P
    >>> R = P + Q
    >>> print(R)
    <Point
        x: 1f660f74ade02f05292a3b4f224e2a90a66a239842c34f3669350cd74a1701aa
        y: 54dcb6934bdce048f109e466f5f17b43b2d3b4465d371563b45b3cd32c341100
        point on 'secp256k1' curve>

.. automodule:: ecpy.curves
   :members:
