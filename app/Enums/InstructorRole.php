<?php

namespace App\Enums;

/**
 * The part an instructor plays in an event: every event has one lead
 * and any number of assistants.
 */
enum InstructorRole: string
{
    case Lead = 'lead';
    case Assistant = 'assistant';

    /**
     * Human-readable role shown in the interface.
     */
    public function label(): string
    {
        return match ($this) {
            self::Lead => 'Ведущий',
            self::Assistant => 'Помощник',
        };
    }
}
