<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Events\ChangeSet;
use App\Events\EventDescription;
use App\Models\Certification;
use App\Models\User;

/**
 * A certification was renamed, hidden or shown again.
 */
class CertificationUpdated extends AbstractDomainEvent
{
    /**
     * The attributes as they are named in a notice. Attributes without a label are not mentioned.
     *
     * @var array<string, string>
     */
    private const LABELS = [
        'name' => 'название',
        'is_active' => 'доступность',
    ];

    public function __construct(public Certification $certification, public ChangeSet $changes, ?User $actor)
    {
        parent::__construct($actor);
    }

    /**
     * Announce what the last save changed. A save that changed nothing is not announced.
     */
    public static function dispatchChanges(Certification $certification, ?User $actor): void
    {
        $changes = ChangeSet::fromModel($certification);

        if ($changes->isNotEmpty()) {
            static::dispatch($certification, $changes, $actor);
        }
    }

    public function describe(): ?EventDescription
    {
        $changed = self::changedLabels($this->changes, self::LABELS);

        if ($changed === null) {
            return null;
        }

        return new EventDescription("Изменена сертификация «{$this->certification->name}»: {$changed}", route('settings.certifications.index'), []);
    }
}
