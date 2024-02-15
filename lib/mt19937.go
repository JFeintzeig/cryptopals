package cryptopals

type MT19937 struct {
	w, n, m, r int
	a          uint64
	u          int
	d          uint64
	s          int
	b          uint64
	t          int
	c          uint64
	l          int
	f          uint64
	wMask      uint64
	upperMask  uint64
	lowerMask  uint64
	state      []uint64
	index      int
}

func (mt *MT19937) initialize(seed uint64) {
	mt.state = make([]uint64, mt.n)
	mt.state[0] = seed
	for i := 1; i < mt.n; i++ {
		mt.state[i] = mt.f*(mt.state[i-1]^(mt.state[i-1]>>(mt.w-2))) + uint64(i)
		mt.state[i] &= mt.wMask
	}
}

func (mt *MT19937) update() {
	for i := range mt.state {
		mt.state[i] = mt.state[(i+mt.m)%mt.n] ^ (mt.AMult((mt.state[i] & mt.upperMask) | (mt.state[(i+1)%mt.n] & mt.lowerMask)))
	}
	mt.index = 0
}

func (mt *MT19937) AMult(x uint64) uint64 {
	if (x & 0x1) == 0x0 {
		return x >> 1
	} else {
		return (x >> 1) ^ mt.a
	}
}

func (mt *MT19937) temper(x uint64) uint64 {
	y := x ^ ((x >> mt.u) & mt.d)
	y = y ^ ((y << mt.s) & mt.b)
	y = y ^ ((y << mt.t) & mt.c)
	return (y ^ (y >> mt.l)) & mt.wMask
}

func (mt *MT19937) Rand() uint64 {
	if mt.index >= mt.n {
		mt.update()
	}
	rand := mt.wMask & mt.temper(mt.state[mt.index])
	mt.index += 1
	return rand
}

func NewMT19937(nbits int, seed uint64) *MT19937 {
	var w, n, m, r, u, s, t, l int
	var a, d, b, c, f uint64
	if nbits == 32 {
		w = 32
		n = 624
		m = 397
		r = 31
		a = uint64(0x9908B0DF)
		u = 11
		d = uint64(0xFFFFFFFF)
		s = 7
		b = uint64(0x9D2C5680)
		t = 15
		c = uint64(0xEFC60000)
		l = 18
		f = uint64(1812433253)
	} else if nbits == 64 {
		w = 64
		n = 312
		m = 156
		r = 31
		a = uint64(0xB5026F5AA96619E9)
		u = 29
		d = uint64(0x5555555555555555)
		s = 17
		b = uint64(0x71D67FFFEDA60000)
		t = 37
		c = uint64(0xFFF7EEE000000000)
		l = 43
		f = uint64(6364136223846793005)
	} else {
		panic("nbits must be 32 or 64")
	}

	wMask := uint64((1 << w) - 1)
	lowerMask := uint64((1 << r) - 1)
	upperMask := (^lowerMask) & wMask

	mt := MT19937{
		w: w, n: n, m: m, r: r, a: a, u: u, d: d,
		s: s, b: b, t: t, c: c, l: l, f: f,
		wMask:     wMask,
		upperMask: upperMask,
		lowerMask: lowerMask,
		index:     n,
	}

	mt.initialize(seed)
	return &mt
}
