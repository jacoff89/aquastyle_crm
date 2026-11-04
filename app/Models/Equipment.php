<?php

namespace App\Models;

use App\Enums\EquipmentStatus;
use Database\Factories\EquipmentFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * An item in the equipment registry: a regulator, a BCD, a wetsuit and so on.
 * It is kept at a location and may be assigned to an instructor who is responsible for it.
 * Items are written off rather than deleted, so the registry keeps their history.
 */
#[Fillable(['name', 'inventory_number', 'size', 'status', 'location_id', 'instructor_id', 'notes'])]
class Equipment extends Model
{
    /** @use HasFactory<EquipmentFactory> */
    use HasFactory;

    /**
     * @var array<string, mixed>
     */
    protected $attributes = [
        'status' => 'in_use',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'status' => EquipmentStatus::class,
        ];
    }

    /**
     * Where the item is kept.
     *
     * @return BelongsTo<Location, $this>
     */
    public function location(): BelongsTo
    {
        return $this->belongsTo(Location::class);
    }

    /**
     * The instructor the item is assigned to.
     *
     * @return BelongsTo<User, $this>
     */
    public function instructor(): BelongsTo
    {
        return $this->belongsTo(User::class, 'instructor_id');
    }
}
