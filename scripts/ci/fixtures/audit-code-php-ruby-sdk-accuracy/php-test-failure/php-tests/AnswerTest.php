<?php
declare(strict_types=1);
use PHPUnit\Framework\TestCase;
final class AnswerTest extends TestCase
{
    public function testAnswer(): void
    {
        self::assertSame(41, answer());
    }
}
