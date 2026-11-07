<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
use App\Models\Exercise;
use App\Models\User;

/**
 * An exercise was added in the settings.
 */
class ExerciseCreated extends AbstractDomainEvent
{
    public function __construct(public Exercise $exercise, ?User $actor)
    {
        parent::__construct($actor);
    }

    public function describe(): ?EventDescription
    {
        return new EventDescription("Новое упражнение «{$this->exercise->name}»", route('settings.exercises.index'));
    }
}
