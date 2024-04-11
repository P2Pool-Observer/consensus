package utils

import (
	"golang.org/x/sync/errgroup"
	"runtime"
	"sync/atomic"
)

func SplitWork(routines int, workSize uint64, do func(workIndex uint64, routineIndex int) error, init func(routines, routineIndex int) error) error {
	if routines <= 0 {
		routines = max(runtime.NumCPU()-routines, 4)
	}

	if workSize < uint64(routines) {
		routines = int(workSize)
	}

	var counter atomic.Uint64

	for routineIndex := 0; routineIndex < routines; routineIndex++ {
		if err := init(routines, routineIndex); err != nil {
			return err
		}
	}

	var eg errgroup.Group

	for routineIndex := 0; routineIndex < routines; routineIndex++ {
		innerRoutineIndex := routineIndex
		eg.Go(func() error {
			var err error

			for {
				workIndex := counter.Add(1)
				if workIndex > workSize {
					return nil
				}

				if err = do(workIndex-1, innerRoutineIndex); err != nil {
					return err
				}
			}
		})
	}
	return eg.Wait()
}
