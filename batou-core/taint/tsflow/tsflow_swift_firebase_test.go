package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — Firebase iOS SDK access-control bypass / SSRF tests (CWE-639/918)
// =========================================================================
//
// Firebase iOS SDK exposes path-based addressing across Firestore, Realtime
// Database, and Cloud Storage. When user-controlled values are interpolated
// into these paths/URLs, attackers can bypass per-document/per-prefix security
// rules (NoSQL access-control bypass, CWE-639) or pivot to attacker-owned
// buckets (SSRF, CWE-918). FCM topic subscription is a trust-boundary case
// (CWE-501) where user input controls which broadcast messages a device
// receives.
//
// The safe pattern is to pin path prefixes / collection IDs / topic names to
// constants and rely on Firebase Security Rules with `request.auth.uid` to
// scope reads/writes — never derive the path from untrusted input.

// Firestore.document(_:) — absolute slash-separated path with tainted segment.
func TestSwift_Firebase_Firestore_Document_Tainted(t *testing.T) {
	code := `
import FirebaseFirestore

func loadUser(input: String) async throws {
    let ref = Firestore.firestore().document("users/\(input)/private")
    let doc = try await ref.getDocument()
    _ = doc
}
`
	flows := Analyze(code, "/app/UserService.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected Firestore path-injection flow for input -> Firestore.firestore().document()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Firestore.collection(_:) — collection path with tainted name.
func TestSwift_Firebase_Firestore_Collection_Tainted(t *testing.T) {
	code := `
import FirebaseFirestore

func loadGroup(input: String) async throws {
    let col = Firestore.firestore().collection("\(input)")
    let snap = try await col.getDocuments()
    _ = snap
}
`
	flows := Analyze(code, "/app/GroupService.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected Firestore collection-injection flow for input -> Firestore.firestore().collection()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Firestore.collectionGroup(_:) — cross-database group ID with tainted value.
func TestSwift_Firebase_Firestore_CollectionGroup_Tainted(t *testing.T) {
	code := `
import FirebaseFirestore

func searchAll(input: String) async throws {
    let q = Firestore.firestore().collectionGroup("\(input)")
    let snap = try await q.getDocuments()
    _ = snap
}
`
	flows := Analyze(code, "/app/SearchService.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected Firestore collectionGroup-injection flow for input -> collectionGroup()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Realtime Database — Database.reference(withPath:) with tainted path.
func TestSwift_Firebase_RTDB_ReferenceWithPath_Tainted(t *testing.T) {
	code := `
import FirebaseDatabase

func loadNode(input: String) async {
    let ref = Database.database().reference(withPath: "/users/\(input)/secrets")
    ref.observeSingleEvent(of: .value) { snapshot in
        print(snapshot)
    }
}
`
	flows := Analyze(code, "/app/NodeService.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected RTDB reference(withPath:) injection flow for input -> Database.database().reference(withPath:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Realtime Database — DatabaseReference.child(_:) with tainted segment.
func TestSwift_Firebase_RTDB_Child_Tainted(t *testing.T) {
	code := `
import FirebaseDatabase

func loadChild(input: String) async {
    let databaseReference = Database.database().reference()
    let userRef = databaseReference.child("users/\(input)/private")
    userRef.observeSingleEvent(of: .value) { snap in
        print(snap)
    }
}
`
	flows := Analyze(code, "/app/ChildService.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected RTDB DatabaseReference.child() injection flow for input -> databaseReference.child()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Cloud Storage — Storage.reference(forURL:) with tainted bucket URL (SSRF).
func TestSwift_Firebase_Storage_ReferenceForURL_Tainted(t *testing.T) {
	code := `
import FirebaseStorage

func loadAsset(input: String) async throws {
    let ref = Storage.storage().reference(forURL: "\(input)")
    let _ = try await ref.data(maxSize: 1024 * 1024)
}
`
	flows := Analyze(code, "/app/AssetService.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected Storage reference(forURL:) SSRF flow for input -> Storage.storage().reference(forURL:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Cloud Storage — StorageReference.child(_:) with tainted path segment.
func TestSwift_Firebase_Storage_Child_Tainted(t *testing.T) {
	code := `
import FirebaseStorage

func uploadAvatar(input: String, data: Data) async throws {
    let storageReference = Storage.storage().reference()
    let userRef = storageReference.child("avatars/\(input).jpg")
    let _ = try await userRef.putDataAsync(data)
}
`
	flows := Analyze(code, "/app/AvatarService.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Storage child() path-injection flow for input -> storageReference.child()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Cloud Messaging — Messaging.subscribe(toTopic:) with tainted topic.
func TestSwift_Firebase_Messaging_Subscribe_Tainted(t *testing.T) {
	code := `
import FirebaseMessaging

func subscribeUser(input: String) async {
    Messaging.messaging().subscribe(toTopic: "\(input)") { error in
        if let error = error { print(error) }
    }
}
`
	flows := Analyze(code, "/app/PushService.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected FCM topic-subscription flow for input -> Messaging.messaging().subscribe(toTopic:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: constant Firestore document path with no tainted interpolation should
// NOT produce a swift.firebase.firestore.* flow even though the input
// parameter is read elsewhere.
func TestSwift_Firebase_Firestore_ConstantPath_Safe(t *testing.T) {
	code := `
import FirebaseFirestore

func loadDefaults(input: String) async throws {
    print(input)
    let doc = try await Firestore.firestore().document("config/defaults").getDocument()
    _ = doc
}
`
	flows := Analyze(code, "/app/DefaultsService.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery &&
			(f.Sink.ID == "swift.firebase.firestore.document" ||
				f.Sink.ID == "swift.firebase.firestore.collection" ||
				f.Sink.ID == "swift.firebase.firestore.collectiongroup") {
			t.Errorf("expected NO swift.firebase.firestore.* flow when path is a constant, got sink %s", f.Sink.ID)
		}
	}
}
