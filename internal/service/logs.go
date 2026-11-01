package service

import (
	"errors"

	"vault443/internal/journal"
	"vault443/internal/model"
	"vault443/internal/store"
)

// All runtime callbacks receive an immutable session; delayed output from a
// previous process cannot acquire the next user's profile or journal identity.
func (s *Service) beginLog(owner *store.Session, p model.Profile) {
	if s.journal == nil || owner == nil {
		return
	}
	secrets := p.Secrets()
	s.logSession = s.journal.NewSession(owner.UID, p.ID, secrets...)
	s.logOwner = &store.Session{UID: owner.UID, ProfileID: owner.ProfileID}
	if runtime, ok := s.runtime.(interface{ SetLogSession(*journal.Session) }); ok {
		runtime.SetLogSession(s.logSession)
	}
}

func (s *Service) endLog() {
	s.logSession = nil
	s.logOwner = nil
	if runtime, ok := s.runtime.(interface{ SetLogSession(*journal.Session) }); ok {
		runtime.SetLogSession(nil)
	}
}

func (s *Service) log(level, message string) {
	if s.logSession != nil {
		s.logSession.Log(level, message)
	}
}

func (s *Service) logResult(err error, success, failure string) {
	if err != nil {
		s.log("error", failure)
	} else {
		s.log("info", success)
	}
}

// Do not take the service network-operation lock while reading or clearing logs.
// A connection can take seconds; journal access must remain responsive meanwhile.
func (s *Service) GetProfileLogs(c Caller, id, cursor string, limit int) (journal.Page, error) {
	st := s.store.Snapshot()
	if _, ok := st.Profile(&store.Session{UID: c.UID, ProfileID: id}); !ok {
		return journal.Page{}, errors.New("profile not found")
	}
	if s.journal == nil {
		return journal.Page{Entries: []journal.Entry{}, NextCursor: cursor}, nil
	}
	return s.journal.Read(c.UID, id, cursor, limit)
}

func (s *Service) ClearProfileLogs(c Caller, id string) error {
	st := s.store.Snapshot()
	if _, ok := st.Profile(&store.Session{UID: c.UID, ProfileID: id}); !ok {
		return errors.New("profile not found")
	}
	if s.journal == nil {
		s.stateMu.Lock()
		delete(s.worker.failures[c.UID], id)
		delete(s.worker.switchFailures[c.UID], id)
		if op := s.worker.operation; op != nil && s.worker.operationUID == c.UID && op.ProfileID == id {
			op.Failure = nil
		}
		s.stateMu.Unlock()
		s.changed()
		return nil
	}
	if err := s.journal.Clear(c.UID, id); err != nil {
		return err
	}
	epoch := s.journal.Epoch(c.UID, id)
	s.stateMu.Lock()
	if failure, ok := s.worker.failures[c.UID][id]; ok && failure.journalEpoch < epoch {
		delete(s.worker.failures[c.UID], id)
	}
	if failure, ok := s.worker.switchFailures[c.UID][id]; ok && failure.journalEpoch < epoch {
		delete(s.worker.switchFailures[c.UID], id)
	}
	if op := s.worker.operation; op != nil && s.worker.operationUID == c.UID && op.ProfileID == id && op.Failure != nil && op.Failure.journalEpoch < epoch {
		op.Failure = nil
	}
	s.stateMu.Unlock()
	s.changed()
	return nil
}
