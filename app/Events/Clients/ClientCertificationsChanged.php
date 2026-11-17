<?php

namespace App\Events\Clients;

use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
use App\Models\Certification;
use App\Models\Client;
use App\Models\User;

/**
 * Certifications were given to a client or taken away. Changes to the client's own
 * details, the status among them, are announced by ClientUpdated.
 */
class ClientCertificationsChanged extends AbstractDomainEvent
{
    /**
     * @param  list<int>  $attachedCertificationIds
     * @param  list<int>  $detachedCertificationIds
     */
    public function __construct(
        public Client $client,
        public array $attachedCertificationIds,
        public array $detachedCertificationIds,
        ?User $actor,
    ) {
        parent::__construct($actor);
    }

    /**
     * Announce the result of syncing the client's certifications, unless nothing changed.
     *
     * @param  array{attached: array<int, int|string>, detached: array<int, int|string>, updated: array<int, int|string>}  $changes
     */
    public static function dispatchFor(Client $client, array $changes, ?User $actor): void
    {
        if ($changes['attached'] === [] && $changes['detached'] === []) {
            return;
        }

        static::dispatch(
            $client,
            array_map(intval(...), array_values($changes['attached'])),
            array_map(intval(...), array_values($changes['detached'])),
            $actor,
        );
    }

    public function describe(): ?EventDescription
    {
        $parts = [];

        if ($this->attachedCertificationIds !== []) {
            $parts[] = 'добавлены '.self::certificationNames($this->attachedCertificationIds);
        }

        if ($this->detachedCertificationIds !== []) {
            $parts[] = 'убраны '.self::certificationNames($this->detachedCertificationIds);
        }

        return new EventDescription("Сертификации клиента {$this->client->fullName()}: ".implode('; ', $parts), route('clients.show', $this->client), []);
    }

    /**
     * @param  list<int>  $certificationIds
     */
    private static function certificationNames(array $certificationIds): string
    {
        return Certification::query()->whereKey($certificationIds)->ordered()->get()
            ->map(fn (Certification $certification): string => "«{$certification->name}»")
            ->implode(', ');
    }
}
