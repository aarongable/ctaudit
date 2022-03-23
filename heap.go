package main

// Orderable types express a total ordering: any two items of the type can
// be compared and are guaranteed to have an ordering relative to each other.
type Orderable[T any] interface {
	// Before takes another object of the same type, and returns true if this
	// object comes before the other, or false otherwise.
	Before(T) bool
}

type Heap[T Orderable[T]] struct {
	data []T
}

func NewHeap[T Orderable[T]]() *Heap[T] {
	return &Heap[T]{}
}

func (h *Heap[T]) Len() int { return len(h.data) }

func (h *Heap[T]) Push(v T) {
	h.data = append(h.data, v)
	h.up(h.Len() - 1)
}

func (h *Heap[T]) Pop() T {
	v := h.data[0]

	n := h.Len() - 1
	if n > 0 {
		h.swap(0, n)
		h.down()
	}
	h.data = h.data[0:n]

	return v
}

func (h *Heap[T]) Peek() T {
	return h.data[0]
}

func parent(i int) int { return (i - 1) / 2 }
func left(i int) int   { return (i * 2) + 1 }
func right(i int) int  { return left(i) + 1 }

func (h *Heap[T]) swap(i, j int) {
	h.data[i], h.data[j] = h.data[j], h.data[i]
}

func (h *Heap[T]) up(jj int) {
	for {
		i := parent(jj)
		if i == jj || !h.data[jj].Before(h.data[i]) {
			break
		}
		h.swap(i, jj)
		jj = i
	}
}

func (h *Heap[T]) down() {
	n := h.Len() - 1
	i1 := 0
	for {
		j1 := left(i1)
		if j1 >= n || j1 < 0 {
			break
		}
		j := j1
		j2 := right(i1)
		if j2 < n && h.data[j2].Before(h.data[j1]) {
			j = j2
		}
		if !h.data[j].Before(h.data[i1]) {
			break
		}
		h.swap(i1, j)
		i1 = j
	}
}
