<?php

namespace App\Models;

use Database\Factories\ExerciseFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

/**
 * A training exercise that is attached to a client on an event, e.g. «Снятие и надевание маски».
 * Administrators maintain the list; hidden exercises are not offered for new attachments
 * but stay on the bookings they were attached to.
 */
#[Fillable(['name', 'is_active'])]
class Exercise extends Model
{
    /** @use HasFactory<ExerciseFactory> */
    use HasFactory;

    /**
     * @var array<string, mixed>
     */
    protected $attributes = [
        'is_active' => true,
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'is_active' => 'boolean',
        ];
    }

    /**
     * @param  Builder<Exercise>  $query
     */
    #[Scope]
    protected function ordered(Builder $query): void
    {
        $query->orderBy('name')->orderBy('id');
    }

    /**
     * @param  Builder<Exercise>  $query
     */
    #[Scope]
    protected function active(Builder $query): void
    {
        $query->where('is_active', true);
    }
}
