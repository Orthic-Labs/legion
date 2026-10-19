public final class KnownAnswerTest {
    private static void equal(String name, int actual) {
        if (actual != 42) throw new AssertionError(name + " expected 42, got " + actual);
        System.out.println("LEGION_ASSERT|" + name + "|pass");
    }
    public static void main(String[] args) {
        equal("java-answer", JavaAnswer.answer());
        equal("kotlin-answer", KotlinAnswer.answer());
        equal("scala-answer", ScalaAnswer.answer());
        System.out.println("LEGION_TEST_DONE|3");
    }
}
