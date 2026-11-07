<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Events\ChangeSet;
use App\Events\EventDescription;
use App\Models\Exercise;
use App\Models\User;

/**
 * An exercise was renamed, hidden or shown again. A change of its event types is
 * announced by ExerciseEventTypesChanged.
 */
class ExerciseUpdated extends AbstractDomainEvent
{
    /**
     * The exercise's attributes as they are named in a notice. Attributes without a label
     * (or announced by an event of their own) are not mentioned.
     *
     * @var array<string, string>
     */
    private const LABELS = [
        'name' => 'название',
        'is_active' => 'доступность',
    ];

    public function __construct(public Exercise $exercise, public ChangeSet $changes, ?User $actor)
    {
        parent::__construct($actor);
    }

    /**
     * Announce what the last save of the exercise changed. A save that changed nothing is not announced.
     */
    public static function dispatchChanges(Exercise $exercise, ?User $actor): void
    {
        $changes = ChangeSet::fromModel($exercise);

        if ($changes->isNotEmpty()) {
            static::dispatch($exercise, $changes, $actor);
        }
    }

    public function describe(): ?EventDescription
    {
        $changed = self::changedLabels($this->changes, self::LABELS);

        if ($changed === null) {
            return null;
        }

        return new EventDescription("Изменено упражнение «{$this->exercise->name}»: {$changed}", route('settings.exercises.index'), []);
    }
}
