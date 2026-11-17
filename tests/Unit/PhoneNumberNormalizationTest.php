<?php

namespace Tests\Unit;

use App\Casts\PhoneNumber;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class PhoneNumberNormalizationTest extends TestCase
{
    /**
     * @return array<string, array{string, string}>
     */
    public static function validPhones(): array
    {
        return [
            'international with separators' => ['+7 912 345-67-89', '+79123456789'],
            'international without separators' => ['+79123456789', '+79123456789'],
            'leading eight' => ['8 (912) 345-67-89', '+79123456789'],
            'leading seven without plus' => ['7 912 345 67 89', '+79123456789'],
            'ten digits without country code' => ['912 345 67 89', '+79123456789'],
            'dots and brackets' => ['(912).345.67.89', '+79123456789'],
            'surrounding spaces' => ['  +7 912 345-67-89 ', '+79123456789'],
            'foreign number with plus' => ['+1 234 567 8901', '+12345678901'],
            'foreign number with a long country code' => ['+380 44 123 45 67', '+380441234567'],
        ];
    }

    #[DataProvider('validPhones')]
    public function test_phone_is_brought_to_one_form(string $phone, string $expected): void
    {
        $this->assertSame($expected, PhoneNumber::normalize($phone));
    }

    /**
     * @return array<string, array{?string}>
     */
    public static function invalidPhones(): array
    {
        return [
            'null' => [null],
            'empty' => [''],
            'only spaces' => ['   '],
            'letters' => ['912-abc-45'],
            'no digits' => ['abc'],
            'too short' => ['12-34'],
            'foreign number without plus' => ['44 20 7946 0958'],
            'eleven digits that are not Russian, without plus' => ['12345678901'],
            'russian number with plus that is too short' => ['+7 912 345'],
            'russian number with plus that is too long' => ['+7 912 345 67 89 12'],
            'foreign number that is too short' => ['+1 234 56'],
            'foreign number that is too long' => ['+1 234 567 890 123 456'],
            'country code that starts with zero' => ['+0 123 456 789'],
            'plus in the middle' => ['7+9123456789'],
            'two pluses' => ['++79123456789'],
        ];
    }

    #[DataProvider('invalidPhones')]
    public function test_invalid_phone_is_not_normalized(?string $phone): void
    {
        $this->assertNull(PhoneNumber::normalize($phone));
    }
}
