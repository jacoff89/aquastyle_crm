<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
use App\Models\ClientStatus;
use App\Models\User;

/**
 * A client status was moved one place up or down the list. The list is renumbered with a bulk
 * update, which Eloquent's model events do not see, so this event is the only trace of it.
 */
class ClientStatusesReordered extends AbstractDomainEvent
{
    /**
     * @param  'up'|'down'  $direction
     */
    public function __construct(public ClientStatus $clientStatus, public string $direction, ?User $actor)
    {
        parent::__construct($actor);
    }

    public function describe(): ?EventDescription
    {
        $where = $this->direction === 'up' ? 'выше' : 'ниже';

        return new EventDescription("Статус «{$this->clientStatus->name}» перемещён {$where} в списке", route('settings.client-statuses.index'));
    }
}
