public final class KnownAnswerTest {
    // Protocol markers for the harness, not debug output.
    private static final java.io.PrintStream PROTOCOL = System.out;
    private static void equal(String name, int actual) {
        if (actual != 42) throw new AssertionError(name + " expected 42, got " + actual);
        PROTOCOL.println("LEGION_ASSERT|" + name + "|pass");
    }
    public static void main(String[] args) {
        equal("java-answer", JavaAnswer.answer());
        equal("kotlin-answer", KotlinAnswer.answer());
        equal("scala-answer", ScalaAnswer.answer());
        PROTOCOL.println("LEGION_TEST_DONE|3");
    }
}
