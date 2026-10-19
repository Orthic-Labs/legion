<?php
declare(strict_types=1);
use PHPUnit\Framework\TestCase;
final class AnswerTest extends TestCase
{
    public function testAnswer(): void
    {
        $this->expectException(TypeError::class);
        answer();
    }
}
