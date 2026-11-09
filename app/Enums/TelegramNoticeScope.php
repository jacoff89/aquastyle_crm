<?php

namespace App\Enums;

use App\Models\User;

/**
 * Which notices of a chosen type reach a user in Telegram: the ones that concern them,
 * or, for an administrator, every one of that type.
 */
enum TelegramNoticeScope: string
{
    case Mine = 'mine';
    case All = 'all';

    /**
     * Human-readable scope shown in the settings.
     */
    public function label(): string
    {
        return match ($this) {
            self::Mine => 'Касающиеся меня',
            self::All => 'Все',
        };
    }

    /**
     * The scopes the user can choose: every notice of a type is for administrators only,
     * because only they see every notice.
     *
     * @return list<self>
     */
    public static function availableTo(User $user): array
    {
        return $user->isAdmin() ? self::cases() : [self::Mine];
    }

    /**
     * Value and label of every scope the user can choose, for the settings page.
     *
     * @return list<array{value: string, label: string}>
     */
    public static function optionsFor(User $user): array
    {
        return array_map(
            fn (self $scope): array => ['value' => $scope->value, 'label' => $scope->label()],
            self::availableTo($user),
        );
    }
}
