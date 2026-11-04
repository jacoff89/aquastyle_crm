<?php

namespace App\Enums;

/**
 * The state of an item of equipment: in use, away for repair, or written off.
 * Written-off items stay in the registry so their history is not lost.
 */
enum EquipmentStatus: string
{
    case InUse = 'in_use';
    case Repair = 'repair';
    case WrittenOff = 'written_off';

    /**
     * Human-readable status shown in the interface.
     */
    public function label(): string
    {
        return match ($this) {
            self::InUse => 'В работе',
            self::Repair => 'В ремонте',
            self::WrittenOff => 'Списано',
        };
    }

    /**
     * Value and label of every status, for the select in the interface.
     *
     * @return list<array{value: string, label: string}>
     */
    public static function options(): array
    {
        return array_map(fn (self $status): array => ['value' => $status->value, 'label' => $status->label()], self::cases());
    }
}
