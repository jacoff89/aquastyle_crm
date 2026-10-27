<?php

namespace Tests\Unit;

use App\Models\Client;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class ClientPhoneNormalizationTest extends TestCase
{
    /**
     * @return array<string, array{string, string}>
     */
    public static function phones(): array
    {
        return [
            'international with separators' => ['+7 912 345-67-89', '79123456789'],
            'international without separators' => ['+79123456789', '79123456789'],
            'leading eight' => ['8 (912) 345-67-89', '79123456789'],
            'ten digits without country code' => ['912 345 67 89', '79123456789'],
            'dots and brackets' => ['(912).345.67.89', '79123456789'],
            'foreign number is kept as digits' => ['+1 234 567 8901', '12345678901'],
            'short number is kept as digits' => ['12-34-56', '123456'],
            'no digits' => ['abc', ''],
        ];
    }

    #[DataProvider('phones')]
    public function test_phone_is_reduced_to_digits_in_one_form(string $phone, string $expected): void
    {
        $this->assertSame($expected, Client::normalizePhone($phone));
    }
}
