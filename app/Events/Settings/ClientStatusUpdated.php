<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Events\ChangeSet;
use App\Events\EventDescription;
use App\Models\ClientStatus;
use App\Models\User;

/**
 * A client status was renamed, hidden or shown again.
 */
class ClientStatusUpdated extends AbstractDomainEvent
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

    public function __construct(public ClientStatus $clientStatus, public ChangeSet $changes, ?User $actor)
    {
        parent::__construct($actor);
    }

    /**
     * Announce what the last save changed. A save that changed nothing is not announced.
     */
    public static function dispatchChanges(ClientStatus $clientStatus, ?User $actor): void
    {
        $changes = ChangeSet::fromModel($clientStatus);

        if ($changes->isNotEmpty()) {
            static::dispatch($clientStatus, $changes, $actor);
        }
    }

    public function describe(): ?EventDescription
    {
        $changed = self::changedLabels($this->changes, self::LABELS);

        if ($changed === null) {
            return null;
        }

        return new EventDescription("Изменён статус «{$this->clientStatus->name}»: {$changed}", route('settings.client-statuses.index'), []);
    }
}
