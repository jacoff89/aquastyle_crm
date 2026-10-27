<?php

namespace App\Models;

use App\Enums\InstructorRole;
use Illuminate\Database\Eloquent\Relations\Pivot;

/**
 * An instructor taking part in an event, with the part they play in it.
 */
class EventInstructor extends Pivot
{
    /**
     * @var bool
     */
    public $incrementing = true;

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'role' => InstructorRole::class,
        ];
    }
}
