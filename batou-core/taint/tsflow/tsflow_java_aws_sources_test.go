package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Second-order taint sources for additional AWS SDK reads in Java
// (parity with the Kotlin AWS source set + DynamoDB transactGetItems and
// S3 v2 getObjectAsBytes). Items/payloads read back from S3, SQS, Kinesis,
// and DynamoDB carry attacker-controlled data (uploads, queue/stream
// producers, previously-stored attributes) and must be treated as untrusted.
//
// All positive tests use a command-injection sink (Runtime.getRuntime().exec)
// and the assign-then-concatenate shape to avoid (a) the isWebHandlerFunc
// `executeQuery(`/`Query(` substring auto-taint trigger and (b) taint loss
// through chained calls on a tainted receiver.

func TestJava_AWSReadSources_Registered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangJava)
	if cat == nil {
		t.Fatal("Java catalog not loaded")
	}
	found := map[string]bool{}
	for _, s := range cat.Sources() {
		found[s.ID] = true
	}
	want := []string{
		"java.aws.s3.client.getobjectasbytes",
		"java.aws.s3.s3object.objectcontent",
		"java.aws.sqs.message.body",
		"java.aws.kinesis.record.data",
		"java.dynamodb.client.batchgetitem",
		"java.dynamodb.client.transactgetitems",
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected source: %s", id)
		}
	}
}

// ---------- DynamoDB batchGetItem (CWE-78 command injection) ----------

func TestJava_AWS_DynamoDB_BatchGetItem_CommandInjection(t *testing.T) {
	code := `
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

public class Reader {
    public void run(DynamoDbClient dynamoDb, Object request) throws Exception {
        Object data = dynamoDb.batchGetItem(request);
        Runtime.getRuntime().exec("cat " + data);
    }
}
`
	flows := Analyze(code, "/app/Reader.java", rules.LangJava)
	if !hasFlowFromSource(flows, "java.dynamodb.client.batchgetitem", taint.SnkCommand) {
		t.Errorf("expected command injection flow from DynamoDbClient.batchGetItem -> Runtime.exec; flows=%+v", flows)
	}
}

// ---------- DynamoDB transactGetItems (CWE-78 command injection) ----------

func TestJava_AWS_DynamoDB_TransactGetItems_CommandInjection(t *testing.T) {
	code := `
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

public class Reader {
    public void run(DynamoDbClient dynamoDb, Object request) throws Exception {
        Object data = dynamoDb.transactGetItems(request);
        Runtime.getRuntime().exec("cat " + data);
    }
}
`
	flows := Analyze(code, "/app/Reader.java", rules.LangJava)
	if !hasFlowFromSource(flows, "java.dynamodb.client.transactgetitems", taint.SnkCommand) {
		t.Errorf("expected command injection flow from DynamoDbClient.transactGetItems -> Runtime.exec; flows=%+v", flows)
	}
}

// ---------- S3 v2 getObjectAsBytes (CWE-78 command injection) ----------

func TestJava_AWS_S3_GetObjectAsBytes_CommandInjection(t *testing.T) {
	code := `
import software.amazon.awssdk.services.s3.S3Client;

public class Loader {
    public void load(S3Client s3, Object request) throws Exception {
        Object payload = s3.getObjectAsBytes(request);
        Runtime.getRuntime().exec("process " + payload);
    }
}
`
	flows := Analyze(code, "/app/Loader.java", rules.LangJava)
	if !hasFlowFromSource(flows, "java.aws.s3.client.getobjectasbytes", taint.SnkCommand) {
		t.Errorf("expected command injection flow from S3Client.getObjectAsBytes -> Runtime.exec; flows=%+v", flows)
	}
}

// ---------- S3 v1 S3Object.getObjectContent (CWE-78 command injection) ----------

func TestJava_AWS_S3_ObjectContent_CommandInjection(t *testing.T) {
	code := `
import com.amazonaws.services.s3.model.S3Object;

public class Fetcher {
    public void fetch(S3Object s3Object) throws Exception {
        Object content = s3Object.getObjectContent();
        Runtime.getRuntime().exec("run " + content);
    }
}
`
	flows := Analyze(code, "/app/Fetcher.java", rules.LangJava)
	if !hasFlowFromSource(flows, "java.aws.s3.s3object.objectcontent", taint.SnkCommand) {
		t.Errorf("expected command injection flow from S3Object.getObjectContent -> Runtime.exec; flows=%+v", flows)
	}
}

// ---------- SQS v2 Message.body (CWE-78 command injection) ----------

func TestJava_AWS_SQS_MessageBody_CommandInjection(t *testing.T) {
	code := `
import software.amazon.awssdk.services.sqs.model.Message;

public class Worker {
    public void consume(Message message) throws Exception {
        String payload = message.body();
        Runtime.getRuntime().exec("echo " + payload);
    }
}
`
	flows := Analyze(code, "/app/Worker.java", rules.LangJava)
	if !hasFlowFromSource(flows, "java.aws.sqs.message.body", taint.SnkCommand) {
		t.Errorf("expected command injection flow from SQS Message.body -> Runtime.exec; flows=%+v", flows)
	}
}

// ---------- Kinesis Record.data (CWE-78 command injection) ----------

func TestJava_AWS_Kinesis_RecordData_CommandInjection(t *testing.T) {
	code := `
import software.amazon.awssdk.services.kinesis.model.Record;

public class Consumer {
    public void process(Record record) throws Exception {
        Object data = record.data();
        Runtime.getRuntime().exec("run " + data);
    }
}
`
	flows := Analyze(code, "/app/Consumer.java", rules.LangJava)
	if !hasFlowFromSource(flows, "java.aws.kinesis.record.data", taint.SnkCommand) {
		t.Errorf("expected command injection flow from Kinesis Record.data -> Runtime.exec; flows=%+v", flows)
	}
}

// ---------- Negative control: constant input, no source -> no flow ----------

func TestJava_AWS_ReadSources_ConstantNoFlow(t *testing.T) {
	code := `
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

public class Safe {
    public void run() throws Exception {
        String data = "static-constant-value";
        Runtime.getRuntime().exec("cat " + data);
    }
}
`
	flows := Analyze(code, "/app/Safe.java", rules.LangJava)
	for _, f := range flows {
		switch f.Source.ID {
		case "java.dynamodb.client.batchgetitem",
			"java.dynamodb.client.transactgetitems",
			"java.aws.s3.client.getobjectasbytes",
			"java.aws.s3.s3object.objectcontent",
			"java.aws.sqs.message.body",
			"java.aws.kinesis.record.data":
			t.Errorf("unexpected AWS-read-source flow for constant input: %s", f.Source.ID)
		}
	}
}
