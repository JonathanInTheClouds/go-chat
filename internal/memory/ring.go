package memory

type Ring[T any] struct {
	values []T
	start  int
	count  int
}

func NewRing[T any](capacity int) *Ring[T] {
	if capacity <= 0 {
		capacity = 1
	}

	return &Ring[T]{
		values: make([]T, capacity),
	}
}

func (r *Ring[T]) Append(value T) {
	if len(r.values) == 0 {
		return
	}

	if r.count < len(r.values) {
		index := (r.start + r.count) % len(r.values)
		r.values[index] = value
		r.count++
		return
	}

	r.values[r.start] = value
	r.start = (r.start + 1) % len(r.values)
}

func (r *Ring[T]) Snapshot() []T {
	result := make([]T, 0, r.count)
	for idx := 0; idx < r.count; idx++ {
		result = append(result, r.values[(r.start+idx)%len(r.values)])
	}
	return result
}

func (r *Ring[T]) Len() int {
	return r.count
}
