<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
use App\Models\Certification;
use App\Models\User;

/**
 * A certification was moved one place up or down the list. The list is renumbered with a bulk
 * update, which Eloquent's model events do not see, so this event is the only trace of it.
 */
class CertificationsReordered extends AbstractDomainEvent
{
    /**
     * @param  'up'|'down'  $direction
     */
    public function __construct(public Certification $certification, public string $direction, ?User $actor)
    {
        parent::__construct($actor);
    }

    public function describe(): ?EventDescription
    {
        $where = $this->direction === 'up' ? 'выше' : 'ниже';

        return new EventDescription("Сертификация «{$this->certification->name}» перемещена {$where} в списке", route('settings.certifications.index'));
    }
}
